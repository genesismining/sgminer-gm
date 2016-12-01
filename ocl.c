/*
 * Copyright 2011-2012 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <sys/types.h>

#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>

#include "findnonce.h"
#include "algorithm.h"
#include "ocl.h"
#include "ocl/build_kernel.h"
#include "ocl/binary_kernel.h"
#include "algorithm/neoscrypt.h"
#include "algorithm/pluck.h"
#include "algorithm/yescrypt.h"
#include "algorithm/lyra2rev2.h"
#include "algorithm/equihash.h"

/* FIXME: only here for global config vars, replace with configuration.h
 * or similar as soon as config is in a struct instead of littered all
 * over the global namespace.
 */
#include "miner.h"


#define CL_SET_ARG_N(n, var) do { status |= clSetKernelArg(*kernel, n, sizeof(var), (void *)&var); } while (0)
#define CL_SET_ARG(var) CL_SET_ARG_N(num++, var)


int opt_platform_id = -1;

bool get_opencl_platform(int preferred_platform_id, cl_platform_id *platform) {
  cl_int status;
  cl_uint numPlatforms;
  cl_platform_id *platforms = NULL;
  unsigned int i;
  bool ret = false;

  status = clGetPlatformIDs(0, NULL, &numPlatforms);
  /* If this fails, assume no GPUs. */
  if (status != CL_SUCCESS) {
    applog(LOG_ERR, "Error %d: clGetPlatformsIDs failed (no OpenCL SDK installed?)", status);
    goto out;
  }

  if (numPlatforms == 0) {
    applog(LOG_ERR, "clGetPlatformsIDs returned no platforms (no OpenCL SDK installed?)");
    goto out;
  }

  if (preferred_platform_id >= (int)numPlatforms) {
    applog(LOG_ERR, "Specified platform that does not exist");
    goto out;
  }

  platforms = (cl_platform_id *)malloc(numPlatforms*sizeof(cl_platform_id));
  status = clGetPlatformIDs(numPlatforms, platforms, NULL);
  if (status != CL_SUCCESS) {
    applog(LOG_ERR, "Error %d: Getting Platform Ids. (clGetPlatformsIDs)", status);
    goto out;
  }

  for (i = 0; i < numPlatforms; i++) {
    if (preferred_platform_id >= 0 && (int)i != preferred_platform_id)
      continue;

    *platform = platforms[i];
    ret = true;
    break;
  }
out:
  if (platforms) free(platforms);
  return ret;
}


int clDevicesNum(void) {
  cl_int status;
  char pbuff[256];
  cl_uint numDevices;
  cl_platform_id platform = NULL;
  int ret = -1;

  if (!get_opencl_platform(opt_platform_id, &platform)) {
    goto out;
  }

  status = clGetPlatformInfo(platform, CL_PLATFORM_VENDOR, sizeof(pbuff), pbuff, NULL);
  if (status != CL_SUCCESS) {
    applog(LOG_ERR, "Error %d: Getting Platform Info. (clGetPlatformInfo)", status);
    goto out;
  }

  applog(LOG_INFO, "CL Platform vendor: %s", pbuff);
  status = clGetPlatformInfo(platform, CL_PLATFORM_NAME, sizeof(pbuff), pbuff, NULL);
  if (status == CL_SUCCESS)
    applog(LOG_INFO, "CL Platform name: %s", pbuff);
  status = clGetPlatformInfo(platform, CL_PLATFORM_VERSION, sizeof(pbuff), pbuff, NULL);
  if (status == CL_SUCCESS)
    applog(LOG_INFO, "CL Platform version: %s", pbuff);
  status = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 0, NULL, &numDevices);
  if (status != CL_SUCCESS) {
    applog(LOG_INFO, "Error %d: Getting Device IDs (num)", status);
    goto out;
  }
  applog(LOG_INFO, "Platform devices: %d", numDevices);
  if (numDevices) {
    unsigned int j;
    cl_device_id *devices = (cl_device_id *)malloc(numDevices*sizeof(cl_device_id));

    clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, numDevices, devices, NULL);
    for (j = 0; j < numDevices; j++) {
      clGetDeviceInfo(devices[j], CL_DEVICE_NAME, sizeof(pbuff), pbuff, NULL);
      applog(LOG_INFO, "\t%i\t%s", j, pbuff);
    }
    free(devices);
  }

  ret = numDevices;
out:
  return ret;
}

static cl_int create_opencl_context(cl_context *context, cl_platform_id *platform)
{
  cl_context_properties cps[3] = { CL_CONTEXT_PLATFORM, (cl_context_properties)*platform, 0 };
  cl_int status;

  *context = clCreateContextFromType(cps, CL_DEVICE_TYPE_GPU, NULL, NULL, &status);
  return status;
}

static float get_opencl_version(cl_device_id device)
{
  /* Check for OpenCL >= 1.0 support, needed for global offset parameter usage. */
  char devoclver[1024];
  char *find;
  float version = 1.0;
  cl_int status;

  status = clGetDeviceInfo(device, CL_DEVICE_VERSION, 1024, (void *)devoclver, NULL);
  if (status != CL_SUCCESS) {
    quit(1, "Failed to clGetDeviceInfo when trying to get CL_DEVICE_VERSION");
  }
  find = strstr(devoclver, "OpenCL 1.0");
  if (!find) {
    version = 1.1;
    find = strstr(devoclver, "OpenCL 1.1");
    if (!find)
      version = 1.2;
  }
  return version;
}

static cl_int create_opencl_command_queue(cl_command_queue *command_queue, cl_context *context, cl_device_id *device, cl_command_queue_properties cq_properties)
{
  cl_int status;
  *command_queue = clCreateCommandQueue(*context, *device,
    cq_properties, &status);
  if (status != CL_SUCCESS) /* Try again without OOE enable */
    *command_queue = clCreateCommandQueue(*context, *device, 0, &status);
  return status;
}

// Borrowed from driver-opencl.c
static void set_threads_hashes(unsigned int vectors, unsigned int compute_shaders, size_t *globalThreads,
  unsigned int minthreads, __maybe_unused int *intensity, __maybe_unused int *xintensity,
  __maybe_unused int *rawintensity, algorithm_t *algorithm)
{
  unsigned int threads = 0;
  while (threads < minthreads) {

    if (*rawintensity > 0) {
      threads = *rawintensity;
    }
    else if (*xintensity > 0) {
      threads = compute_shaders * ((algorithm->xintensity_shift) ? (1 << (algorithm->xintensity_shift + *xintensity)) : *xintensity);
    }
    else {
      threads = 1 << (algorithm->intensity_shift + *intensity);
    }

    if (threads < minthreads) {
      if (likely(*intensity < MAX_INTENSITY)) {
        (*intensity)++;
      }
      else {
        threads = minthreads;
      }
    }
  }

  *globalThreads = threads;
}

_clState *initCl(unsigned int gpu, char *name, size_t nameSize, algorithm_t *algorithm)
{
  cl_int status = 0;
  size_t compute_units = 0;
  cl_platform_id platform = NULL;
  struct cgpu_info *cgpu = &gpus[gpu];
  _clState *clState = (_clState *)calloc(1, sizeof(_clState));
  cl_uint preferred_vwidth, numDevices = clDevicesNum();
  cl_device_id *devices = (cl_device_id *)alloca(numDevices * sizeof(cl_device_id));
  build_kernel_data *build_data = (build_kernel_data *)alloca(sizeof(struct _build_kernel_data));
  char **pbuff = (char **)alloca(sizeof(char *) * numDevices), filename[256];

  // sanity check
  if (!get_opencl_platform(opt_platform_id, &platform)) {
    return NULL;
  }

  if (numDevices <= 0) {
    return NULL;
  }

  if (gpu >= numDevices) {
    applog(LOG_ERR, "Invalid GPU %i", gpu);
    return NULL;
  }


  /* Now, get the device list data */

  status = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, numDevices, devices, NULL);
  if (status != CL_SUCCESS) {
    applog(LOG_ERR, "Error %d: Getting Device IDs (list)", status);
    return NULL;
  }

  applog(LOG_INFO, "List of devices:");

  for (int i = 0; i < numDevices; ++i)	{
    size_t tmpsize;
    if (clGetDeviceInfo(devices[i], CL_DEVICE_NAME, 0, NULL, &tmpsize) != CL_SUCCESS) {
      applog(LOG_ERR, "Error while getting the length of the name for GPU #%d.", i);
      return NULL;
    }

    // Does the size include the NULL terminator? Who knows, just add one, it's faster than looking it up.
    pbuff[i] = (char *)alloca(sizeof(char) * (tmpsize + 1));
    if (clGetDeviceInfo(devices[i], CL_DEVICE_NAME, sizeof(char) * tmpsize, pbuff[i], NULL) != CL_SUCCESS) {
      applog(LOG_ERR, "Error while attempting to get device information.");
		  return NULL;
    }

    applog(LOG_INFO, "\t%i\t%s", i, pbuff[i]);
	}

	applog(LOG_INFO, "Selected %d: %s", gpu, pbuff[gpu]);
  strncpy(name, pbuff[gpu], nameSize);

  status = create_opencl_context(&clState->context, &platform);
  if (status != CL_SUCCESS) {
    applog(LOG_ERR, "Error %d: Creating Context. (clCreateContextFromType)", status);
    return NULL;
  }

  status = create_opencl_command_queue(&clState->commandQueue, &clState->context, &devices[gpu], cgpu->algorithm.cq_properties);
  if (status != CL_SUCCESS) {
    applog(LOG_ERR, "Error %d: Creating Command Queue. (clCreateCommandQueue)", status);
    return NULL;
  }

  status = clGetDeviceInfo(devices[gpu], CL_DEVICE_PREFERRED_VECTOR_WIDTH_INT, sizeof(cl_uint), (void *)&preferred_vwidth, NULL);
  if (status != CL_SUCCESS) {
    applog(LOG_ERR, "Error %d: Failed to clGetDeviceInfo when trying to get CL_DEVICE_PREFERRED_VECTOR_WIDTH_INT", status);
    return NULL;
  }
  applog(LOG_DEBUG, "Preferred vector width reported %d", preferred_vwidth);

  status = clGetDeviceInfo(devices[gpu], CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(size_t), (void *)&clState->max_work_size, NULL);
  if (status != CL_SUCCESS) {
    applog(LOG_ERR, "Error %d: Failed to clGetDeviceInfo when trying to get CL_DEVICE_MAX_WORK_GROUP_SIZE", status);
    return NULL;
  }
  applog(LOG_DEBUG, "Max work group size reported %d", (int)(clState->max_work_size));

  status = clGetDeviceInfo(devices[gpu], CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(size_t), (void *)&compute_units, NULL);
  if (status != CL_SUCCESS) {
    applog(LOG_ERR, "Error %d: Failed to clGetDeviceInfo when trying to get CL_DEVICE_MAX_COMPUTE_UNITS", status);
    return NULL;
  }
  // AMD architechture got 64 compute shaders per compute unit.
  // Source: http://www.amd.com/us/Documents/GCN_Architecture_whitepaper.pdf
  clState->compute_shaders = compute_units << 6;
  applog(LOG_INFO, "Maximum work size for this GPU (%d) is %d.", gpu, clState->max_work_size);
	applog(LOG_INFO, "Your GPU (#%d) has %d compute units, and all AMD cards in the 7 series or newer (GCN cards) \
		have 64 shaders per compute unit - this means it has %d shaders.", gpu, compute_units, clState->compute_shaders);

  status = clGetDeviceInfo(devices[gpu], CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof(cl_ulong), (void *)&cgpu->max_alloc, NULL);
  if (status != CL_SUCCESS) {
    applog(LOG_ERR, "Error %d: Failed to clGetDeviceInfo when trying to get CL_DEVICE_MAX_MEM_ALLOC_SIZE", status);
    return NULL;
  }
  applog(LOG_DEBUG, "Max mem alloc size is %lu", (long unsigned int)(cgpu->max_alloc));

  /* Create binary filename based on parameters passed to opencl
   * compiler to ensure we only load a binary that matches what
   * would have otherwise created. The filename is:
   * name + g + lg + lookup_gap + tc + thread_concurrency + nf + nfactor + w + work_size + l + sizeof(long) + .bin
   */

  sprintf(filename, "%s.cl", (!empty_string(cgpu->algorithm.kernelfile) ? cgpu->algorithm.kernelfile : cgpu->algorithm.name));
  applog(LOG_DEBUG, "Using source file %s", filename);

  /* For some reason 2 vectors is still better even if the card says
   * otherwise, and many cards lie about their max so use 256 as max
   * unless explicitly set on the command line. Tahiti prefers 1 */
  if (strstr(name, "Tahiti"))
    preferred_vwidth = 1;
  else if (preferred_vwidth > 2)
    preferred_vwidth = 2;

  /* All available kernels only support vector 1 */
  cgpu->vwidth = 1;

  /* Vectors are hard-set to 1 above. */
  if (likely(cgpu->vwidth))
    clState->vwidth = cgpu->vwidth;
  else {
    clState->vwidth = preferred_vwidth;
    cgpu->vwidth = preferred_vwidth;
  }

  clState->goffset = true;

  clState->wsize = (cgpu->work_size && cgpu->work_size <= clState->max_work_size) ? cgpu->work_size : 256;

  if (!cgpu->opt_lg) {
    applog(LOG_DEBUG, "GPU %d: selecting lookup gap of 2", gpu);
    cgpu->lookup_gap = 2;
  }
  else
    cgpu->lookup_gap = cgpu->opt_lg;

  if ((strcmp(cgpu->algorithm.name, "zuikkis") == 0) && (cgpu->lookup_gap != 2)) {
    applog(LOG_WARNING, "Kernel zuikkis only supports lookup-gap = 2 (currently %d), forcing.", cgpu->lookup_gap);
    cgpu->lookup_gap = 2;
  }

  if ((strcmp(cgpu->algorithm.name, "bufius") == 0) && ((cgpu->lookup_gap != 2) && (cgpu->lookup_gap != 4) && (cgpu->lookup_gap != 8))) {
    applog(LOG_WARNING, "Kernel bufius only supports lookup-gap of 2, 4 or 8 (currently %d), forcing to 2", cgpu->lookup_gap);
    cgpu->lookup_gap = 2;
  }

  // neoscrypt TC
  if (cgpu->algorithm.type == ALGO_NEOSCRYPT && !cgpu->opt_tc) {
    size_t glob_thread_count;
    long max_int;
    unsigned char type = 0;

    // determine which intensity type to use
    if (cgpu->rawintensity > 0) {
      glob_thread_count = cgpu->rawintensity;
      max_int = glob_thread_count;
      type = 2;
    }
    else if (cgpu->xintensity > 0) {
      glob_thread_count = clState->compute_shaders * ((cgpu->algorithm.xintensity_shift) ? (1UL << (cgpu->algorithm.xintensity_shift + cgpu->xintensity)) : cgpu->xintensity);
      max_int = cgpu->xintensity;
      type = 1;
    }
    else {
      glob_thread_count = 1UL << (cgpu->algorithm.intensity_shift + cgpu->intensity);
      max_int = ((cgpu->dynamic) ? MAX_INTENSITY : cgpu->intensity);
    }

    glob_thread_count = ((glob_thread_count < cgpu->work_size) ? cgpu->work_size : glob_thread_count);

    // if TC * scratchbuf size is too big for memory... reduce to max
    if ((glob_thread_count * NEOSCRYPT_SCRATCHBUF_SIZE) >= (uint64_t)cgpu->max_alloc) {

      /* Selected intensity will not run on this GPU. Not enough memory.
       * Adapt the memory setting. */
      // depending on intensity type used, reduce the intensity until it fits into the GPU max_alloc
      switch (type) {
        //raw intensity
      case 2:
        while ((glob_thread_count * NEOSCRYPT_SCRATCHBUF_SIZE) > (uint64_t)cgpu->max_alloc) {
          --glob_thread_count;
        }

        max_int = glob_thread_count;
        cgpu->rawintensity = glob_thread_count;
        break;

        //x intensity
      case 1:
        glob_thread_count = cgpu->max_alloc / NEOSCRYPT_SCRATCHBUF_SIZE;
        max_int = glob_thread_count / clState->compute_shaders;

        while (max_int && ((clState->compute_shaders * (1UL << max_int)) > glob_thread_count)) {
          --max_int;
        }

        /* Check if max_intensity is >0. */
        if (max_int < MIN_XINTENSITY) {
          applog(LOG_ERR, "GPU %d: Max xintensity is below minimum.", gpu);
          max_int = MIN_XINTENSITY;
        }

        cgpu->xintensity = max_int;
        glob_thread_count = clState->compute_shaders * (1UL << max_int);
        break;

      default:
        glob_thread_count = cgpu->max_alloc / NEOSCRYPT_SCRATCHBUF_SIZE;
        while (max_int && ((1UL << max_int) & glob_thread_count) == 0) {
          --max_int;
        }

        /* Check if max_intensity is >0. */
        if (max_int < MIN_INTENSITY) {
          applog(LOG_ERR, "GPU %d: Max intensity is below minimum.", gpu);
          max_int = MIN_INTENSITY;
        }

        cgpu->intensity = max_int;
        glob_thread_count = 1UL << max_int;
        break;
      }
    }

    // TC is glob thread count
    cgpu->thread_concurrency = glob_thread_count;

    applog(LOG_DEBUG, "GPU %d: computing max. global thread count to %u", gpu, (unsigned)(cgpu->thread_concurrency));

  }

  // pluck TC
  else if (cgpu->algorithm.type == ALGO_PLUCK && !cgpu->opt_tc) {
    size_t glob_thread_count;
    long max_int;
    unsigned char type = 0;

    // determine which intensity type to use
    if (cgpu->rawintensity > 0) {
      glob_thread_count = cgpu->rawintensity;
      max_int = glob_thread_count;
      type = 2;
    }
    else if (cgpu->xintensity > 0) {
      glob_thread_count = clState->compute_shaders * ((cgpu->algorithm.xintensity_shift) ? (1UL << (cgpu->algorithm.xintensity_shift + cgpu->xintensity)) : cgpu->xintensity);
      max_int = cgpu->xintensity;
      type = 1;
    }
    else {
      glob_thread_count = 1UL << (cgpu->algorithm.intensity_shift + cgpu->intensity);
      max_int = ((cgpu->dynamic) ? MAX_INTENSITY : cgpu->intensity);
    }

    glob_thread_count = ((glob_thread_count < cgpu->work_size) ? cgpu->work_size : glob_thread_count);

    // if TC * scratchbuf size is too big for memory... reduce to max
    if ((glob_thread_count * PLUCK_SCRATCHBUF_SIZE) >= (uint64_t)cgpu->max_alloc) {

      /* Selected intensity will not run on this GPU. Not enough memory.
      * Adapt the memory setting. */
      // depending on intensity type used, reduce the intensity until it fits into the GPU max_alloc
      switch (type) {
        //raw intensity
      case 2:
        while ((glob_thread_count * PLUCK_SCRATCHBUF_SIZE) > (uint64_t)cgpu->max_alloc) {
          --glob_thread_count;
        }

        max_int = glob_thread_count;
        cgpu->rawintensity = glob_thread_count;
        break;

        //x intensity
      case 1:
        glob_thread_count = cgpu->max_alloc / PLUCK_SCRATCHBUF_SIZE;
        max_int = glob_thread_count / clState->compute_shaders;

        while (max_int && ((clState->compute_shaders * (1UL << max_int)) > glob_thread_count)) {
          --max_int;
        }

        /* Check if max_intensity is >0. */
        if (max_int < MIN_XINTENSITY) {
          applog(LOG_ERR, "GPU %d: Max xintensity is below minimum.", gpu);
          max_int = MIN_XINTENSITY;
        }

        cgpu->xintensity = max_int;
        glob_thread_count = clState->compute_shaders * (1UL << max_int);
        break;

      default:
        glob_thread_count = cgpu->max_alloc / PLUCK_SCRATCHBUF_SIZE;
        while (max_int && ((1UL << max_int) & glob_thread_count) == 0) {
          --max_int;
        }

        /* Check if max_intensity is >0. */
        if (max_int < MIN_INTENSITY) {
          applog(LOG_ERR, "GPU %d: Max intensity is below minimum.", gpu);
          max_int = MIN_INTENSITY;
        }

        cgpu->intensity = max_int;
        glob_thread_count = 1UL << max_int;
        break;
      }
    }

    // TC is glob thread count
    cgpu->thread_concurrency = glob_thread_count;

    applog(LOG_DEBUG, "GPU %d: computing max. global thread count to %u", gpu, (unsigned)(cgpu->thread_concurrency));
  }

  // Yescrypt TC
  else if ((cgpu->algorithm.type == ALGO_YESCRYPT ||
            algorithm->type == ALGO_YESCRYPT_MULTI) && !cgpu->opt_tc) {
    size_t glob_thread_count;
    long max_int;
    unsigned char type = 0;

      // determine which intensity type to use
    if (cgpu->rawintensity > 0) {
      glob_thread_count = cgpu->rawintensity;
      max_int = glob_thread_count;
      type = 2;
    }
    else if (cgpu->xintensity > 0) {
      glob_thread_count = clState->compute_shaders * ((cgpu->algorithm.xintensity_shift) ? (1UL << (cgpu->algorithm.xintensity_shift + cgpu->xintensity)) : cgpu->xintensity);
      max_int = cgpu->xintensity;
      type = 1;
    }
    else {
      glob_thread_count = 1UL << (cgpu->algorithm.intensity_shift + cgpu->intensity);
      max_int = ((cgpu->dynamic) ? MAX_INTENSITY : cgpu->intensity);
    }

    glob_thread_count = ((glob_thread_count < cgpu->work_size) ? cgpu->work_size : glob_thread_count);

    // if TC * scratchbuf size is too big for memory... reduce to max
    if ((glob_thread_count * YESCRYPT_SCRATCHBUF_SIZE) >= (uint64_t)cgpu->max_alloc) {

      /* Selected intensity will not run on this GPU. Not enough memory.
      * Adapt the memory setting. */
      // depending on intensity type used, reduce the intensity until it fits into the GPU max_alloc
      switch (type) {
        //raw intensity
      case 2:
        while ((glob_thread_count * YESCRYPT_SCRATCHBUF_SIZE) > (uint64_t)cgpu->max_alloc) {
          --glob_thread_count;
        }

        max_int = glob_thread_count;
        cgpu->rawintensity = glob_thread_count;
        break;

        //x intensity
      case 1:
        glob_thread_count = cgpu->max_alloc / YESCRYPT_SCRATCHBUF_SIZE;
        max_int = glob_thread_count / clState->compute_shaders;

        while (max_int && ((clState->compute_shaders * (1UL << max_int)) > glob_thread_count)) {
          --max_int;
        }

        /* Check if max_intensity is >0. */
        if (max_int < MIN_XINTENSITY) {
          applog(LOG_ERR, "GPU %d: Max xintensity is below minimum.", gpu);
          max_int = MIN_XINTENSITY;
        }

        cgpu->xintensity = max_int;
        glob_thread_count = clState->compute_shaders * (1UL << max_int);
        break;

      default:
        glob_thread_count = cgpu->max_alloc / YESCRYPT_SCRATCHBUF_SIZE;
        while (max_int && ((1UL << max_int) & glob_thread_count) == 0) {
          --max_int;
        }

        /* Check if max_intensity is >0. */
        if (max_int < MIN_INTENSITY) {
          applog(LOG_ERR, "GPU %d: Max intensity is below minimum.", gpu);
          max_int = MIN_INTENSITY;
        }

        cgpu->intensity = max_int;
        glob_thread_count = 1UL << max_int;
        break;
      }
    }

    // TC is glob thread count
    cgpu->thread_concurrency = glob_thread_count;

    applog(LOG_DEBUG, "GPU %d: computing max. global thread count to %u", gpu, (unsigned)(cgpu->thread_concurrency));
  }

  // Lyra2re v2 TC
  else if (cgpu->algorithm.type == ALGO_LYRA2REV2 && !cgpu->opt_tc) {
    size_t glob_thread_count;
    long max_int;
    unsigned char type = 0;

    // determine which intensity type to use
    if (cgpu->rawintensity > 0) {
      glob_thread_count = cgpu->rawintensity;
      max_int = glob_thread_count;
      type = 2;
    }
    else if (cgpu->xintensity > 0) {
      glob_thread_count = clState->compute_shaders * ((cgpu->algorithm.xintensity_shift) ? (1UL << (cgpu->algorithm.xintensity_shift + cgpu->xintensity)) : cgpu->xintensity);
      max_int = cgpu->xintensity;
      type = 1;
    }
    else {
      glob_thread_count = 1UL << (cgpu->algorithm.intensity_shift + cgpu->intensity);
      max_int = ((cgpu->dynamic) ? MAX_INTENSITY : cgpu->intensity);
    }

    glob_thread_count = ((glob_thread_count < cgpu->work_size) ? cgpu->work_size : glob_thread_count);

    // if TC * scratchbuf size is too big for memory... reduce to max
    if ((glob_thread_count * LYRA_SCRATCHBUF_SIZE) >= (uint64_t)cgpu->max_alloc) {

      /* Selected intensity will not run on this GPU. Not enough memory.
      * Adapt the memory setting. */
      // depending on intensity type used, reduce the intensity until it fits into the GPU max_alloc
      switch (type) {
        //raw intensity
      case 2:
        while ((glob_thread_count * LYRA_SCRATCHBUF_SIZE) > (uint64_t)cgpu->max_alloc) {
          --glob_thread_count;
        }

        max_int = glob_thread_count;
        cgpu->rawintensity = glob_thread_count;
        break;

        //x intensity
      case 1:
        glob_thread_count = cgpu->max_alloc / LYRA_SCRATCHBUF_SIZE;
        max_int = glob_thread_count / clState->compute_shaders;

        while (max_int && ((clState->compute_shaders * (1UL << max_int)) > glob_thread_count)) {
          --max_int;
        }

        /* Check if max_intensity is >0. */
        if (max_int < MIN_XINTENSITY) {
          applog(LOG_ERR, "GPU %d: Max xintensity is below minimum.", gpu);
          max_int = MIN_XINTENSITY;
        }

        cgpu->xintensity = max_int;
        glob_thread_count = clState->compute_shaders * (1UL << max_int);
        break;

      default:
        glob_thread_count = cgpu->max_alloc / LYRA_SCRATCHBUF_SIZE;
        while (max_int && ((1UL << max_int) & glob_thread_count) == 0) {
          --max_int;
        }

        /* Check if max_intensity is >0. */
        if (max_int < MIN_INTENSITY) {
          applog(LOG_ERR, "GPU %d: Max intensity is below minimum.", gpu);
          max_int = MIN_INTENSITY;
        }

        cgpu->intensity = max_int;
        glob_thread_count = 1UL << max_int;
        break;
      }
    }

    // TC is glob thread count
    cgpu->thread_concurrency = glob_thread_count;

    applog(LOG_DEBUG, "GPU %d: computing max. global thread count to %u", gpu, (unsigned)(cgpu->thread_concurrency));
  }
  else if (!cgpu->opt_tc) {
    unsigned int sixtyfours;

    sixtyfours = cgpu->max_alloc / 131072 / 64 / (algorithm->n / 1024) - 1;
    cgpu->thread_concurrency = sixtyfours * 64;
    if (cgpu->shaders && cgpu->thread_concurrency > cgpu->shaders) {
      cgpu->thread_concurrency -= cgpu->thread_concurrency % cgpu->shaders;

      if (cgpu->thread_concurrency > cgpu->shaders * 5) {
        cgpu->thread_concurrency = cgpu->shaders * 5;
      }
    }
    applog(LOG_DEBUG, "GPU %d: selecting thread concurrency of %d", gpu, (int)(cgpu->thread_concurrency));
  }
  else {
    cgpu->thread_concurrency = cgpu->opt_tc;
  }

  build_data->context = clState->context;
  build_data->device = &devices[gpu];

  // Build information
  strcpy(build_data->source_filename, filename);
	strcpy(build_data->platform, name);
	strcpy(build_data->sgminer_path, sgminer_path);

  build_data->kernel_path = (*opt_kernel_path) ? opt_kernel_path : NULL;
  build_data->work_size = clState->wsize;
  build_data->opencl_version = get_opencl_version(devices[gpu]);

  strcpy(build_data->binary_filename, filename);
	build_data->binary_filename[strlen(filename) - 3] = 0x00;		// And one NULL terminator, cutting off the .cl suffix.
	strcat(build_data->binary_filename, pbuff[gpu]);

  if (clState->goffset) {
    strcat(build_data->binary_filename, "g");
  }

  set_base_compiler_options(build_data);
  if (algorithm->set_compile_options) {
    algorithm->set_compile_options(build_data, cgpu, algorithm);
  }

  strcat(build_data->binary_filename, ".bin");
  applog(LOG_DEBUG, "Using binary file %s", build_data->binary_filename);

  // Load program from file or build it if it doesn't exist
  if (!(clState->program = load_opencl_binary_kernel(build_data))) {
    applog(LOG_NOTICE, "Building binary %s", build_data->binary_filename);

    if (!(clState->program = build_opencl_kernel(build_data, filename))) {
      return NULL;
    }

    // If it doesn't work, oh well, build it again next run
    save_opencl_kernel(build_data, clState->program);
  }

  // Load kernels
  applog(LOG_NOTICE, "Initialising kernel %s with nfactor %d, n %d",
    filename, algorithm->nfactor, algorithm->n);

  /* get a kernel object handle for a kernel with the given name */
  if (algorithm->type == ALGO_EQUIHASH) {
    clState->kernel = clCreateKernel(clState->program, "kernel_sols", &status);
    if (status != CL_SUCCESS) {
      applog(LOG_ERR, "Error %d: Creating Kernel \"kernel_sols\" from program. (clCreateKernel)", status);
      return NULL;
    }
    char *kernel_names[] = {"kernel_init_ht",
                            "kernel_round0", "kernel_round1", "kernel_round2",
                            "kernel_round3", "kernel_round4", "kernel_round5",
                            "kernel_round6", "kernel_round7", "kernel_round8"};
    clState->n_extra_kernels = 1 + 9;
    clState->extra_kernels = (cl_kernel *)malloc(sizeof(cl_kernel) * clState->n_extra_kernels);
    for (int i = 0; i < clState->n_extra_kernels; i++) {
      clState->extra_kernels[i] = clCreateKernel(clState->program, kernel_names[i], &status);
      if (status != CL_SUCCESS) {
	applog(LOG_ERR, "Error %d: Creating Kernel \"%s\" from program. (clCreateKernel)", status, kernel_names[i]);
        return NULL;
      }
    }

    char buffer[32];
    clState->CLbuffer0 = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, HT_SIZE, NULL, &status);
    snprintf(buffer, sizeof(buffer), "CLbuffer0");
    if (status != CL_SUCCESS)
      goto out;
    clState->buffer1 = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, HT_SIZE, NULL, &status);
    snprintf(buffer, sizeof(buffer), "buffer1");
    if (status != CL_SUCCESS)
      goto out;
    clState->buffer2 = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, NR_ROWS, NULL, &status);
    snprintf(buffer, sizeof(buffer), "buffer2");
    if (status != CL_SUCCESS)
      goto out;
    clState->buffer3 = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, NR_ROWS, NULL, &status); 
    snprintf(buffer, sizeof(buffer), "buffer3");
    if (status != CL_SUCCESS)
      goto out;
    clState->padbuffer8 = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, 2 * sizeof(uint32_t), NULL, &status);
    snprintf(buffer, sizeof(buffer), "padbuffer8");
    if (status != CL_SUCCESS)
      goto out;
    clState->MidstateBuf = clCreateBuffer(clState->context, CL_MEM_READ_ONLY, 140, NULL, &status);  // TODO: decrease buffer size to 64 bytes
    snprintf(buffer, sizeof(buffer), "MidstateBuf");
    if (status != CL_SUCCESS)
      goto out;
    clState->outputBuffer = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, MAX(sizeof(sols_t), BUFFERSIZE), NULL, &status);
    snprintf(buffer, sizeof(buffer), "outputBuffer");
    if (status != CL_SUCCESS)
      goto out;

    unsigned int num = 0;
    cl_kernel *kernel = &clState->kernel;
    CL_SET_ARG(clState->CLbuffer0);
    CL_SET_ARG(clState->buffer1);
    CL_SET_ARG(clState->outputBuffer);
    CL_SET_ARG(clState->buffer2);
    CL_SET_ARG(clState->buffer3);

    if (status != CL_SUCCESS) {
      applog(LOG_ERR, "Error %d: Setting Kernel arguments for ALGO_EQUIHASH failed. (clSetKernelArg)", status);
      return NULL;
    }

    clState->devid = cgpu->device_id;
    return clState;
out:
    applog(LOG_ERR, "Error %d: Creating Buffer \"%s\" failed. (clCreateBuffer)", status, buffer);
    return NULL;
  }
  else {
    clState->kernel = clCreateKernel(clState->program, "search", &status);
    if (status != CL_SUCCESS) {
      applog(LOG_ERR, "Error %d: Creating Kernel from program. (clCreateKernel)", status);
      return NULL;
    }
  
    clState->n_extra_kernels = algorithm->n_extra_kernels;
    if (clState->n_extra_kernels > 0) {
      unsigned int i;
      char kernel_name[9]; // max: search99 + 0x0

      clState->extra_kernels = (cl_kernel *)malloc(sizeof(cl_kernel)* clState->n_extra_kernels);

      for (i = 0; i < clState->n_extra_kernels; i++) {
        snprintf(kernel_name, 9, "%s%d", "search", i + 1);
        clState->extra_kernels[i] = clCreateKernel(clState->program, kernel_name, &status);
        if (status != CL_SUCCESS) {
          applog(LOG_ERR, "Error %d: Creating ExtraKernel #%d from program. (clCreateKernel)", status, i);
          return NULL;
        }
      }
    }
  }
    

  if (algorithm->type == ALGO_ETHASH) {
    clState->GenerateDAG = clCreateKernel(clState->program, "GenerateDAG", &status);

    if (status != CL_SUCCESS) {
      applog(LOG_ERR, "Error %d while creating DAG generation kernel.", status);
      return NULL;
    }
  }

  size_t bufsize;
  size_t buf1size;
  size_t buf3size;
  size_t buf2size;
  size_t readbufsize;
  switch (algorithm->type) {
    case ALGO_CRE:
      readbufsize = 168;
      break;
    case ALGO_ETHASH:
      readbufsize = 32;
      break;
    default:
      readbufsize = 128;
  }

  if (algorithm->rw_buffer_size < 0) {
    // calc buffer size for neoscrypt
    if (algorithm->type == ALGO_NEOSCRYPT) {
      /* The scratch/pad-buffer needs 32kBytes memory per thread. */
      bufsize = NEOSCRYPT_SCRATCHBUF_SIZE * cgpu->thread_concurrency;

      /* This is the input buffer. For neoscrypt this is guaranteed to be
       * 80 bytes only. */
      readbufsize = 80;

      applog(LOG_DEBUG, "Neoscrypt buffer sizes: %lu RW, %lu R", (unsigned long)bufsize, (unsigned long)readbufsize);
      // scrypt/n-scrypt
    }
    else if (algorithm->type == ALGO_PLUCK) {
      /* The scratch/pad-buffer needs 32kBytes memory per thread. */
      bufsize = PLUCK_SCRATCHBUF_SIZE * cgpu->thread_concurrency;

      /* This is the input buffer. For pluck this is guaranteed to be
      * 80 bytes only. */
      readbufsize = 80;

      applog(LOG_DEBUG, "pluck buffer sizes: %lu RW, %lu R", (unsigned long)bufsize, (unsigned long)readbufsize);
      // scrypt/n-scrypt
    }
    else if (algorithm->type == ALGO_YESCRYPT || algorithm->type == ALGO_YESCRYPT_MULTI) {
      /* The scratch/pad-buffer needs 32kBytes memory per thread. */
      bufsize = YESCRYPT_SCRATCHBUF_SIZE * cgpu->thread_concurrency;
      buf1size = PLUCK_SECBUF_SIZE * cgpu->thread_concurrency;
      buf2size = 128 * 8 * 8 * cgpu->thread_concurrency;
      buf3size= 8 * 8 * 4 * cgpu->thread_concurrency;
      /* This is the input buffer. For yescrypt this is guaranteed to be
      * 80 bytes only. */
      readbufsize = 80;

      applog(LOG_DEBUG, "yescrypt buffer sizes: %lu RW, %lu R", (unsigned long)bufsize, (unsigned long)readbufsize);
      // scrypt/n-scrypt
    }
    else if (algorithm->type == ALGO_LYRA2REV2) {
      /* The scratch/pad-buffer needs 32kBytes memory per thread. */
      bufsize = LYRA_SCRATCHBUF_SIZE * cgpu->thread_concurrency;
      buf1size = 4* 8 * cgpu->thread_concurrency; //matrix

      /* This is the input buffer. For yescrypt this is guaranteed to be
      * 80 bytes only. */
      readbufsize = 80;

      applog(LOG_DEBUG, "lyra2REv2 buffer sizes: %lu RW, %lu RW", (unsigned long)bufsize, (unsigned long)buf1size);
      // scrypt/n-scrypt
    }
    else {
      size_t ipt = (algorithm->n / cgpu->lookup_gap + (algorithm->n % cgpu->lookup_gap > 0));
      bufsize = 128 * ipt * cgpu->thread_concurrency;
      applog(LOG_DEBUG, "Scrypt buffer sizes: %lu RW, %lu R", (unsigned long)bufsize, (unsigned long)readbufsize);
    }
  }
  else {
    bufsize = (size_t)algorithm->rw_buffer_size;
    applog(LOG_DEBUG, "Buffer sizes: %lu RW, %lu R", (unsigned long)bufsize, (unsigned long)readbufsize);
  }

  clState->padbuffer8 = NULL;
  clState->buffer1 = NULL;
  clState->buffer2 = NULL;
  clState->buffer3 = NULL;

  if (bufsize > 0) {
    applog(LOG_DEBUG, "Creating read/write buffer sized %lu", (unsigned long)bufsize);
    /* Use the max alloc value which has been rounded to a power of
     * 2 greater >= required amount earlier */
    if (bufsize > cgpu->max_alloc) {
      applog(LOG_WARNING, "Maximum buffer memory device %d supports says %lu",
	gpu, (unsigned long)(cgpu->max_alloc));
      applog(LOG_WARNING, "Your settings come to %lu", (unsigned long)bufsize);
    }

    if (algorithm->type == ALGO_YESCRYPT || algorithm->type == ALGO_YESCRYPT_MULTI) {
      // need additionnal buffers
      clState->buffer1 = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, buf1size, NULL, &status);
      if (status != CL_SUCCESS && !clState->buffer1) {
	applog(LOG_DEBUG, "Error %d: clCreateBuffer (buffer1), decrease TC or increase LG", status);
	return NULL;
      }

      clState->buffer2 = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, buf2size, NULL, &status);
      if (status != CL_SUCCESS && !clState->buffer2) {
	applog(LOG_DEBUG, "Error %d: clCreateBuffer (buffer2), decrease TC or increase LG", status);
	return NULL;
      }

      clState->buffer3 = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, buf3size, NULL, &status);
      if (status != CL_SUCCESS && !clState->buffer3) {
	applog(LOG_DEBUG, "Error %d: clCreateBuffer (buffer3), decrease TC or increase LG", status);
	return NULL;
      }
    }
    else if (algorithm->type == ALGO_LYRA2REV2) {
      // need additionnal buffers
      clState->buffer1 = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, buf1size, NULL, &status);
      if (status != CL_SUCCESS && !clState->buffer1) {
	applog(LOG_DEBUG, "Error %d: clCreateBuffer (buffer1), decrease TC or increase LG", status);
	return NULL;
      }
    }
    else {
      clState->buffer1 = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, bufsize, NULL, &status); // we don't need that much just tired...
      if (status != CL_SUCCESS && !clState->buffer1) {
	applog(LOG_DEBUG, "Error %d: clCreateBuffer (buffer1), decrease TC or increase LG", status);
	return NULL;
      }
    }

    /* This buffer is weird and might work to some degree even if
     * the create buffer call has apparently failed, so check if we
     * get anything back before we call it a failure. */
    clState->padbuffer8 = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, bufsize, NULL, &status);
    if (status != CL_SUCCESS && !clState->padbuffer8) {
      applog(LOG_ERR, "Error %d: clCreateBuffer (padbuffer8), decrease TC or increase LG", status);
      return NULL;
    }
  }
  
  if (algorithm->type == ALGO_CRYPTONIGHT) {
    size_t GlobalThreads;
    readbufsize = 76UL;
		
    set_threads_hashes(1, clState->compute_shaders, &GlobalThreads, 1, &cgpu->intensity, &cgpu->xintensity, &cgpu->rawintensity, &cgpu->algorithm);
		
    for (int i = 0; i < 4; ++i) {
      clState->BranchBuffer[i] = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, sizeof(cl_uint) * (GlobalThreads + 2), NULL, &status);
			
      if (status != CL_SUCCESS) {
        applog(LOG_ERR, "Error %d when creating branch buffer %d.\n", status, i);
        return NULL;
      }
    }
		
    clState->States = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, 200 * GlobalThreads, NULL, &status);
		
    if(status != CL_SUCCESS) {
      applog(LOG_ERR, "Error %d when creating Cryptonight state buffer.\n", status);
      return NULL;
    }
		
    clState->Scratchpads = clCreateBuffer(clState->context, CL_MEM_READ_WRITE, (1 << 21) * GlobalThreads, NULL, &status);
		
    if(status != CL_SUCCESS) {
      applog(LOG_ERR, "Error %d when creating Cryptonight scratchpads buffer.\n", status);
      return NULL;
    }
  }
  
  applog(LOG_DEBUG, "Using read buffer sized %lu", (unsigned long)readbufsize);
  clState->CLbuffer0 = clCreateBuffer(clState->context, CL_MEM_READ_ONLY, readbufsize, NULL, &status);
  if (status != CL_SUCCESS) {
    applog(LOG_ERR, "Error %d: clCreateBuffer (CLbuffer0)", status);
    return NULL;
  }

  clState->devid = cgpu->device_id;

  size_t buffersize = MAX(sizeof(sols_t), BUFFERSIZE);
  applog(LOG_DEBUG, "Using output buffer sized %lu", buffersize);
  clState->outputBuffer = clCreateBuffer(clState->context, CL_MEM_WRITE_ONLY, buffersize, NULL, &status);
  if (status != CL_SUCCESS) {
    applog(LOG_ERR, "Error %d: clCreateBuffer (outputBuffer)", status);
    return NULL;
  }

  return clState;
}

