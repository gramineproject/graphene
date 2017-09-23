#!/usr/bin/awk -f
BEGIN{
	while(getline < "BLOCKED") {
		test = $1$2$3
		blocked[test]
	}

	if (SGX)  {
	    pal_str = "./pal_loader SGX"
	} else {
	    pal_str = "./pal_loader"
	}
}

NF && ! /^#/ {
	test = $2$3
	if($1=="splice02") {
        s = pal_str
		for (i=2; i<=NF; i++) {
			s = s " " $i
			if($i=="|") {
				i++
				s = s " " pal_str " " $i
			}
		}
		print s
    }
	else if(! (test in blocked)) {
		s = pal_str
		for (i=2; i<=NF; i++) {
			s = s " " $i
		}
		print s
	}
}
