#include <stdint.h>
#include <stdbool.h>
#include <dirent.h>

#include "miner.h"

bool has_sysfs_hwcontrols = false;
bool opt_reorder = false;
int opt_hysteresis = 3;
int opt_targettemp = 80;
int opt_overheattemp = 90;  

int sysfs_gpu_engineclock(int gpu) { }
int sysfs_gpu_memclock(int gpu) { }
float sysfs_gpu_vddc(int gpu) { }
int sysfs_gpu_activity(int gpu) { }
int sysfs_gpu_fanspeed(int gpu) { return(-1); }

int sysfs_set_vddc(int gpu, float fVddc) { }
int sysfs_set_engineclock(int gpu, int iEngineClock) { }
int sysfs_set_memoryclock(int gpu, int iMemoryClock) { }
int sysfs_set_powertune(int gpu, int iPercentage) { }

#ifndef __linux__

void GetGPUHWMonPath(char **HWMonPath, uint32_t GPUIdx)
{
  *HWMonPath = NULL;
}

#else

// Must be freed by caller unless NULL
void GetGPUHWMonPath(char **HWMonPath, uint32_t GPUIdx)
{
  DIR *hwmon;
  char TempPath[256];
  struct dirent *inner_hwmon;
  
  // Set it to NULL (indicating failure) until we need to use it
  *HWMonPath = NULL;
  
  sprintf(TempPath, "/sys/class/drm/card%d/device/hwmon", GPUIdx);
  
  hwmon = opendir(TempPath); 
  if(hwmon == NULL)
    return;
  
  for(;;)
  {
    inner_hwmon = readdir(hwmon);
    if (inner_hwmon == NULL)
      return;
    if (inner_hwmon->d_type != DT_DIR)
      continue;
    if (!memcmp(inner_hwmon->d_name, "hwmon", 5))
      break;
  }
  
  *HWMonPath = (char *)malloc(sizeof(char) * (256 + strlen(inner_hwmon->d_name)));
  sprintf(*HWMonPath, "/sys/class/drm/card%d/device/hwmon/%s", GPUIdx, inner_hwmon->d_name);
  return;
}

#endif

int ReadSysFSFile(uint8_t *Buffer, char *Filename, uint32_t BufSize)
{
  FILE *fd;
  int BytesRead;
  
  fd = fopen(Filename, "rb");
  if(!fd)
    return -1;
  
  BytesRead = fread(Buffer, sizeof(uint8_t), BufSize, fd);
  
  fclose(fd);
  
  return BytesRead;
}

int WriteSysFSFile(uint8_t *Buffer, char *Filename, uint32_t BufSize)
{
  FILE *fd;
  int BytesWritten;
  
  fd = fopen(Filename, "wb");
  if(!fd)
    return -1;
  
  BytesWritten = fwrite(Buffer, sizeof(uint8_t), BufSize, fd);
  
  fclose(fd);
  
  return BytesWritten;
}

float sysfs_gpu_temp(int gpu)
{
  char TempFileName[513];
  char TempBuf[33];
  int BytesRead;
  
  snprintf(TempFileName, 512, "%s/temp1_input", gpus[gpu].sysfs_info.HWMonPath);
  
  BytesRead = ReadSysFSFile(TempBuf, TempFileName, 32);
  
  if (BytesRead <= 0)
    return 0.f;
  
  TempBuf[BytesRead] = 0x00;
  return strtof(TempBuf, NULL) / 1000.f;
}

int fanpercent_to_speed(int gpu, float percent)
{
  int min = gpus[gpu].sysfs_info.MinFanSpeed;
  int max = gpus[gpu].sysfs_info.MaxFanSpeed;

  float range = max - min;
  float res = percent / 100.f * range + min + 0.5f;
  return res;
}

float fanspeed_to_percent(int gpu, int speed)
{
  int min = gpus[gpu].sysfs_info.MinFanSpeed;
  int max = gpus[gpu].sysfs_info.MaxFanSpeed;

  float range = max - min;
  float res = (speed - min) / range * 100.f;
  return res;
}

float sysfs_gpu_fanpercent(int gpu)
{
  char PWM1FileName[513], SpeedStr[33];
  int BytesRead, Speed;
    
  snprintf(PWM1FileName, 512, "%s/pwm1", gpus[gpu].sysfs_info.HWMonPath);
  
  BytesRead = ReadSysFSFile(SpeedStr, PWM1FileName, 32);
  
  if(BytesRead <= 0)
    return -1;
  
  SpeedStr[BytesRead] = 0x00;
  
  Speed = strtoul(SpeedStr, NULL, 10);
  
  return fanspeed_to_percent(gpu, Speed);
}

int sysfs_set_fanspeed(int gpu, float FanSpeed)
{
  char PWM1FileName[513], Setting[33];
  int speed = fanpercent_to_speed(gpu, FanSpeed);
  
  gpus[gpu].sysfs_info.TgtFanSpeed = FanSpeed;
  
  snprintf(PWM1FileName, 512, "%s/pwm1", gpus[gpu].sysfs_info.HWMonPath);
  snprintf(Setting, 32, "%d", speed);
  
  return (WriteSysFSFile(Setting, PWM1FileName, strlen(Setting)) > 0 ? 0 : -1);
}

/* Returns whether the fanspeed is optimal already or not. The fan_window bool
 * tells us whether the current fanspeed is in the target range for fanspeeds.
 */
static bool sysfs_fan_autotune(int gpu, int temp, float fanpercent, int lasttemp, bool *fan_window)
{
  struct cgpu_info *cgpu = &gpus[gpu];
  gpu_sysfs_info *SysFSInfo = &gpus[gpu].sysfs_info;
  int tdiff = temp - lasttemp;
  int top = gpus[gpu].gpu_fan;
  int bot = gpus[gpu].min_fan;
  float newpercent = SysFSInfo->TgtFanSpeed;//fanpercent;
  float iMin = 0, iMax = 100;
    
  if (temp > SysFSInfo->OverHeatTemp && fanpercent < iMax) {
    applog(LOG_WARNING, "Overheat detected on GPU %d, increasing fan to 100%% (temp was %d, overtemp is %d)\n", gpu, temp, SysFSInfo->OverHeatTemp);
    newpercent = iMax;

    dev_error(cgpu, REASON_DEV_OVER_HEAT);
  }
  else if (temp > SysFSInfo->TargetTemp && fanpercent < top && tdiff >= 0) {
    applog(LOG_DEBUG, "Temperature over target, increasing fanspeed");
    if (temp > SysFSInfo->TargetTemp + opt_hysteresis)
      newpercent = SysFSInfo->TgtFanSpeed + 10;
    else
      newpercent = SysFSInfo->TgtFanSpeed + 5;
    
    if (newpercent > top)
      newpercent = top;
  }
  else if (fanpercent > bot && temp < SysFSInfo->TargetTemp - opt_hysteresis) {
    /* Detect large swings of 5 degrees or more and change fan by
     * a proportion more */
    if(tdiff <= 0) {
      applog(LOG_DEBUG, "Temperature %d degrees below target, decreasing fanspeed", opt_hysteresis);
      newpercent = SysFSInfo->TgtFanSpeed - 1 + tdiff / 5;
    }
    else if (tdiff >= 5) {
      applog(LOG_DEBUG, "Temperature climbed %d while below target, increasing fanspeed", tdiff);
      newpercent = SysFSInfo->TgtFanSpeed + tdiff / 5;
    }
  }
  else {
    /* We're in the optimal range, make minor adjustments if the
     * temp is still drifting */
    if (fanpercent > bot && tdiff < 0 && lasttemp < SysFSInfo->TargetTemp) {
      applog(LOG_DEBUG, "Temperature dropping while in target range, decreasing fanspeed");
      newpercent = SysFSInfo->TgtFanSpeed + tdiff;
    }
    else if (fanpercent < top && tdiff > 0 && temp > SysFSInfo->TargetTemp - opt_hysteresis) {
      applog(LOG_DEBUG, "Temperature rising while in target range, increasing fanspeed");
      newpercent = SysFSInfo->TgtFanSpeed + tdiff;
    }
  }

  if (newpercent > iMax)
    newpercent = iMax;
  else if (newpercent < iMin)
    newpercent = iMin;

  if (newpercent <= top)
    *fan_window = true;
  else
    *fan_window = false;

  if (newpercent != fanpercent) {
    applog(LOG_INFO, "Setting GPU %d fan percentage to %d", gpu, newpercent);
    
    set_fanspeed(gpu, newpercent);
    
    /* If the fanspeed is going down and we're below the top speed,
     * consider the fan optimal to prevent minute changes in
     * fanspeed delaying GPU engine speed changes */
    if (newpercent < fanpercent && *fan_window)
      return true;
    
    return false;
  }
  return true;
}

void sysfs_gpu_autotune(int gpu, enum dev_enable *denable)
{
  bool dummy;
  int temp = sysfs_gpu_temp(gpu);
  
  sysfs_fan_autotune(gpu, temp, gpus[gpu].sysfs_info.TgtFanSpeed, gpus[gpu].sysfs_info.LastTemp, &dummy);
  gpu[gpus].sysfs_info.LastTemp = temp;
}

bool sysfs_gpu_stats(int gpu, float *temp, int *engineclock, int *memclock, float *vddc,
         int *activity, int *fanspeed, int *fanpercent, int *powertune)
{
  if (!gpus[gpu].has_sysfs_hwcontrols)
    return false;

  *temp = gpu_temp(gpu);
  *fanspeed = 0;
  *fanpercent = gpu_fanpercent(gpu);
  *engineclock = 0;
  *memclock = 0;
  *vddc = 0;
  *activity = 0;

  return true;
}


bool init_sysfs_hwcontrols(int nDevs)
{
  for(int i = 0; i < nDevs; ++i)
  {
    // Set gpus[i].sysfs_info.HWMonPath
    GetGPUHWMonPath(&gpus[i].sysfs_info.HWMonPath, i);    
    
    if(gpus[i].sysfs_info.HWMonPath)
    {
      char PWMSettingBuf[33];
      char FileNameBuf[513];
      int BytesRead;
      bool MinFanReadSuccess = false;
      
      snprintf(FileNameBuf, 512, "%s/pwm1_min", gpus[i].sysfs_info.HWMonPath);
      BytesRead = ReadSysFSFile(PWMSettingBuf, FileNameBuf, 512);
      
      if(BytesRead > 0)
      {
        PWMSettingBuf[BytesRead] = 0x00;
        gpus[i].sysfs_info.MinFanSpeed = strtoul(PWMSettingBuf, NULL, 10);
        MinFanReadSuccess = true;
      }
      
      snprintf(FileNameBuf, 512, "%s/pwm1_max", gpus[i].sysfs_info.HWMonPath);
      BytesRead = ReadSysFSFile(PWMSettingBuf, FileNameBuf, 512);
      
      if((BytesRead > 0) && MinFanReadSuccess)
      {
        gpus[i].has_sysfs_hwcontrols = true;
        PWMSettingBuf[BytesRead] = 0x00;
        gpus[i].sysfs_info.MaxFanSpeed = strtoul(PWMSettingBuf, NULL, 10);
      }
      
      gpus[i].sysfs_info.LastTemp = sysfs_gpu_temp(i);
      if(!gpus[i].sysfs_info.OverHeatTemp) gpus[i].sysfs_info.OverHeatTemp = opt_overheattemp;
      if(!gpus[i].sysfs_info.TargetTemp) gpus[i].sysfs_info.TargetTemp = opt_targettemp;
    }
    
    if(gpus[i].has_sysfs_hwcontrols) has_sysfs_hwcontrols = true;
  }
  
  if(has_sysfs_hwcontrols)
  {
    gpu_temp = &sysfs_gpu_temp;
    gpu_engineclock = &sysfs_gpu_engineclock;
    gpu_memclock = &sysfs_gpu_memclock;
    gpu_vddc = &sysfs_gpu_vddc;
    gpu_activity = &sysfs_gpu_activity;
    gpu_fanspeed = &sysfs_gpu_fanspeed;
    gpu_fanpercent = &sysfs_gpu_fanpercent;
    set_powertune = &sysfs_set_powertune;
    set_vddc = &sysfs_set_vddc;
    set_fanspeed = &sysfs_set_fanspeed;
    set_engineclock = &sysfs_set_engineclock;
    set_memoryclock = &sysfs_set_memoryclock;
    gpu_stats = &sysfs_gpu_stats;
    gpu_autotune = &sysfs_gpu_autotune;
  }
  
  return(has_sysfs_hwcontrols);  
}
