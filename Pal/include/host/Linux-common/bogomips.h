#ifndef BOGOMIPS_H
#define BOGOMIPS_H

double get_bogomips_from_cpuinfo_buf(const char* buf);
double sanitize_bogomips_value(double);

#endif // BOGOMIPS_H

