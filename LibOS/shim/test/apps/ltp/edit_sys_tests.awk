#!/usr/bin/awk -f
BEGIN{
	while(getline < "BLOCKED") {
		test = $1$2$3
		blocked[test]
	}
}
NF && ! /^#/ {
	test = $2$3
	if($1=="splice02") {
        s = "./pal_loader"
		for (i=2; i<=NF; i++) {
			s = s " " $i
			if($i=="|") {
				i++
				s = s " ./pal_loader " $i
			}
		}
		print s
    }
	else if(! (test in blocked)) {
		s = "./pal_loader"
		for (i=2; i<=NF; i++) {
			s = s " " $i
		}
		print s
	}
}
