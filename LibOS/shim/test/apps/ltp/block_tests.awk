#!/usr/bin/awk -f
BEGIN{
	while(getline < "BLOCKED") {
		test = $1$2$3
		blocked[test]
	}
}
NF && ! /^#/ {
	test = $2$3
	if(!(test in blocked)) {
		s=$1 "_graphene ./pal_loader"
		for (i=2; i<=NF; i++) {
			s = s " " $i
		}
		print s
	}
}
