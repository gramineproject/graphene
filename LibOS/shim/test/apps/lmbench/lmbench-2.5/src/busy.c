volatile int i;

main()
{

	nice(10);
	for (;;) getppid();
	//for (;;) i++;
	exit(i);
}
