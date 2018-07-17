#include"pal.h"
#include"pal_debug.h"
#include<stdio.h>

int main(){
  double num = 5.0;
  double res = num * num;
  
  PAL_HANDLE file1 = DkStreamOpen("file:avxRes", PAL_ACCESS_RDWR, 0, 0, 0); 
  if (file1) {
    DkStreamWrite(file1, 0, sizeof(double), &res, NULL);
    DkObjectClose(file1);
  }
  //pal_printf("double num is %lf\n", num);
  return 1;
}
