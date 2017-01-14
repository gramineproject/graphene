#!/usr/bin/awk -f
BEGIN{
	getline < "PASSED"
	while(getline < "PASSED") {
		split($1$2$3, a, ",")
		test = a[1]
		passed[test]
	}
}
NF && ! /^#/ {
	test = $2$3
	if(test in passed) {
		s=$1 "_graphene ./pal_loader"
		for (i=2; i<=NF; i++) {
			s = s " " $i
		}
		print s
	}
}
