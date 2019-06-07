	/* This .note section tells about vDSO to dynamic linker */
	.section .note.Linux, "a", @note

	.align 4
	.long	6
	.long	4
	.long	0
	.string "Linux"
	.zero	2
	.long	267008	/* LINUX_VERSION_CODE */

	.align 4
	.long	6
	.long	4
	.long	0x100
	.string "Linux"
	.zero	2
	.long	0		/* CONFIG_BUILD_SALT. 0 for now.
					   TODO: make it compile-time configurable */
