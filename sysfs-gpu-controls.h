#ifndef __SYSFS_GPU_CONTROLS_H
#define __SYSFS_GPU_CONTROLS_H

#include "miner.h"

extern bool has_sysfs_hwcontrols;
extern bool opt_reorder;
extern int opt_hysteresis;
extern int opt_targettemp;
extern int opt_overheattemp;

bool init_sysfs_hwcontrols(int nDevs);
extern float sysfs_gpu_temp(int gpu);
extern int sysfs_gpu_engineclock(int gpu);
extern int sysfs_gpu_memclock(int gpu);
extern float sysfs_gpu_vddc(int gpu);
extern int sysfs_gpu_activity(int gpu);
extern int sysfs_gpu_fanspeed(int gpu);
extern int sysfs_gpu_fanpercent(int gpu);
extern int sysfs_set_powertune(int gpu, int iPercentage);

extern bool sysfs_gpu_stats(int gpu, float *temp, int *engineclock, int *memclock, float *vddc,
               int *activity, int *fanspeed, int *fanpercent, int *powertune);
extern void sysfs_gpu_autotune(int gpu, enum dev_enable *denable);

#endif
