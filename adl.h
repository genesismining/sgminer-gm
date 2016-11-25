#ifndef ADL_H
#define ADL_H

#ifdef HAVE_ADL
extern bool adl_active;
extern bool opt_reorder;
extern int opt_hysteresis;
extern int opt_targettemp;
extern int opt_overheattemp;

void init_adl(int nDevs);
float adl_gpu_temp(int gpu);
int adl_gpu_engineclock(int gpu);
int adl_gpu_memclock(int gpu);
float adl_gpu_vddc(int gpu);
int adl_gpu_activity(int gpu);
int adl_gpu_fanspeed(int gpu);
float adl_gpu_fanpercent(int gpu);
int adl_set_powertune(int gpu, int iPercentage);
bool adl_gpu_stats(int gpu, float *temp, int *engineclock, int *memclock, float *vddc,
               int *activity, int *fanspeed, int *fanpercent, int *powertune);
void change_gpusettings(int gpu);
void adl_gpu_autotune(int gpu, enum dev_enable *denable);
void clear_adl(int nDevs);

#else /* HAVE_ADL */

#define adl_active (0)
static inline void init_adl(__maybe_unused int nDevs) {}
static inline void change_gpusettings(__maybe_unused int gpu) { }
static inline void clear_adl(__maybe_unused int nDevs) {}

#endif /* HAVE_ADL */

#endif /* ADL_H */
