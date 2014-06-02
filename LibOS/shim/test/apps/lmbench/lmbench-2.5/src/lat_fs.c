/*
 * Benchmark creates & deletes.
 */

char	*id = "$Id$\n";

#include <math.h>
#include "bench.h"
#include "confidence.h"
#include "timing.h"

#ifndef	ITER
#define	ITER	1000
#endif
#define	S	5

void	mkfile(char *s, int sz);

int
main(int ac, char **av)
{
	static	int	sizes[] = { 0, 1024, 4096, 10*1024 };
	extern	char	*names[];
	int	i, j, pos;
	double	tmp, create_m, delete_m;
	double create_mean, delete_mean, create_var, delete_var;
	double	time_spent;
	
	/* Just a guess. on average, get through ~500 in S time */
	double *create_times = malloc(sizeof(double) * ITER);
	double *delete_times = malloc(sizeof(double) * ITER);

	if (create_times == NULL || delete_times == NULL) {
	  fprintf(stderr, "OUT OF MEMORY\n");
	  return -1;
	}


	if (ac == 2) {
		chdir(av[1]);
	}
	for (i = 0; i < sizeof(sizes)/sizeof(int); ++i) {
	  pos = 0;
		/*
		 * Go around the loop a few times for those really fast Linux
		 * boxes.
		 */
		for (time_spent = create_m = delete_m = 0; time_spent <= S; ) {
			start(0);
			for (j = 0; j < ITER; ++j) {
				mkfile(names[j], sizes[i]);
			}
			tmp = stop(0,0) / 1000000.;
			create_times[pos] = tmp;
			if (create_m == 0 || create_m > tmp) {
				create_m = tmp;
			}
			time_spent += tmp;
			start(0);
			for (j = 0; j < ITER; ++j) {
				unlink(names[j]);
			}
			tmp = stop(0,0) / 1000000.;
			delete_times[pos++] = tmp;
			if (delete_m == 0 || delete_m > tmp) {
				delete_m = tmp;
			}
			time_spent += tmp;
		}

		create_mean = calc_mean_rate(create_times, pos, ITER);
		create_var = calc_variance_rate(create_mean, create_times, pos, ITER);
		delete_mean = calc_mean_rate(delete_times, pos, ITER);
		delete_var = calc_variance_rate(delete_mean, delete_times, pos, ITER);

		fprintf(stderr, "%dk\tN=%d\n", sizes[i]>>10, ITER);

		fprintf(stderr, "\tcreate/time max=%.0f\t mean=%.0f (+/-%.0f)\n",
			ITER / create_m, create_mean,
			ci_width(sqrt(create_var), pos));

		fprintf(stderr, "\tdelete/time max=%0.f\t mean=%.0f (+/-%.0f)\n",
			ITER / delete_m, delete_mean, 
			ci_width(sqrt(delete_var), pos));
	}
	return(0);
}

void
mkfile(char *s, int sz)
{
	int	fd = creat(s, 0666);
	char	buf[128*1024];		/* XXX - track sizes */

	write(fd, buf, sz);
	close(fd);
}

char *names[] = {
"a",	"b",	"c",	"d",	"e",	"f",	"g",	"h",	"i",	"j",
"k",	"l",	"m",	"n",	"o",	"p",	"q",	"r",	"s",	"t",
"u",	"v",	"w",	"x",	"y",	"z",	"aa",	"ab",	"ac",	"ad",
"ae",	"af",	"ag",	"ah",	"ai",	"aj",	"ak",	"al",	"am",	"an",
"ao",	"ap",	"aq",	"ar",	"as",	"at",	"au",	"av",	"aw",	"ax",
"ay",	"az",	"ba",	"bb",	"bc",	"bd",	"be",	"bf",	"bg",	"bh",
"bi",	"bj",	"bk",	"bl",	"bm",	"bn",	"bo",	"bp",	"bq",	"br",
"bs",	"bt",	"bu",	"bv",	"bw",	"bx",	"by",	"bz",	"ca",	"cb",
"cc",	"cd",	"ce",	"cf",	"cg",	"ch",	"ci",	"cj",	"ck",	"cl",
"cm",	"cn",	"co",	"cp",	"cq",	"cr",	"cs",	"ct",	"cu",	"cv",
"cw",	"cx",	"cy",	"cz",	"da",	"db",	"dc",	"dd",	"de",	"df",
"dg",	"dh",	"di",	"dj",	"dk",	"dl",	"dm",	"dn",	"do",	"dp",
"dq",	"dr",	"ds",	"dt",	"du",	"dv",	"dw",	"dx",	"dy",	"dz",
"ea",	"eb",	"ec",	"ed",	"ee",	"ef",	"eg",	"eh",	"ei",	"ej",
"ek",	"el",	"em",	"en",	"eo",	"ep",	"eq",	"er",	"es",	"et",
"eu",	"ev",	"ew",	"ex",	"ey",	"ez",	"fa",	"fb",	"fc",	"fd",
"fe",	"ff",	"fg",	"fh",	"fi",	"fj",	"fk",	"fl",	"fm",	"fn",
"fo",	"fp",	"fq",	"fr",	"fs",	"ft",	"fu",	"fv",	"fw",	"fx",
"fy",	"fz",	"ga",	"gb",	"gc",	"gd",	"ge",	"gf",	"gg",	"gh",
"gi",	"gj",	"gk",	"gl",	"gm",	"gn",	"go",	"gp",	"gq",	"gr",
"gs",	"gt",	"gu",	"gv",	"gw",	"gx",	"gy",	"gz",	"ha",	"hb",
"hc",	"hd",	"he",	"hf",	"hg",	"hh",	"hi",	"hj",	"hk",	"hl",
"hm",	"hn",	"ho",	"hp",	"hq",	"hr",	"hs",	"ht",	"hu",	"hv",
"hw",	"hx",	"hy",	"hz",	"ia",	"ib",	"ic",	"id",	"ie",	"if",
"ig",	"ih",	"ii",	"ij",	"ik",	"il",	"im",	"in",	"io",	"ip",
"iq",	"ir",	"is",	"it",	"iu",	"iv",	"iw",	"ix",	"iy",	"iz",
"ja",	"jb",	"jc",	"jd",	"je",	"jf",	"jg",	"jh",	"ji",	"jj",
"jk",	"jl",	"jm",	"jn",	"jo",	"jp",	"jq",	"jr",	"js",	"jt",
"ju",	"jv",	"jw",	"jx",	"jy",	"jz",	"ka",	"kb",	"kc",	"kd",
"ke",	"kf",	"kg",	"kh",	"ki",	"kj",	"kk",	"kl",	"km",	"kn",
"ko",	"kp",	"kq",	"kr",	"ks",	"kt",	"ku",	"kv",	"kw",	"kx",
"ky",	"kz",	"la",	"lb",	"lc",	"ld",	"le",	"lf",	"lg",	"lh",
"li",	"lj",	"lk",	"ll",	"lm",	"ln",	"lo",	"lp",	"lq",	"lr",
"ls",	"lt",	"lu",	"lv",	"lw",	"lx",	"ly",	"lz",	"ma",	"mb",
"mc",	"md",	"me",	"mf",	"mg",	"mh",	"mi",	"mj",	"mk",	"ml",
"mm",	"mn",	"mo",	"mp",	"mq",	"mr",	"ms",	"mt",	"mu",	"mv",
"mw",	"mx",	"my",	"mz",	"na",	"nb",	"nc",	"nd",	"ne",	"nf",
"ng",	"nh",	"ni",	"nj",	"nk",	"nl",	"nm",	"nn",	"no",	"np",
"nq",	"nr",	"ns",	"nt",	"nu",	"nv",	"nw",	"nx",	"ny",	"nz",
"oa",	"ob",	"oc",	"od",	"oe",	"of",	"og",	"oh",	"oi",	"oj",
"ok",	"ol",	"om",	"on",	"oo",	"op",	"oq",	"or",	"os",	"ot",
"ou",	"ov",	"ow",	"ox",	"oy",	"oz",	"pa",	"pb",	"pc",	"pd",
"pe",	"pf",	"pg",	"ph",	"pi",	"pj",	"pk",	"pl",	"pm",	"pn",
"po",	"pp",	"pq",	"pr",	"ps",	"pt",	"pu",	"pv",	"pw",	"px",
"py",	"pz",	"qa",	"qb",	"qc",	"qd",	"qe",	"qf",	"qg",	"qh",
"qi",	"qj",	"qk",	"ql",	"qm",	"qn",	"qo",	"qp",	"qq",	"qr",
"qs",	"qt",	"qu",	"qv",	"qw",	"qx",	"qy",	"qz",	"ra",	"rb",
"rc",	"rd",	"re",	"rf",	"rg",	"rh",	"ri",	"rj",	"rk",	"rl",
"rm",	"rn",	"ro",	"rp",	"rq",	"rr",	"rs",	"rt",	"ru",	"rv",
"rw",	"rx",	"ry",	"rz",	"sa",	"sb",	"sc",	"sd",	"se",	"sf",
"sg",	"sh",	"si",	"sj",	"sk",	"sl",	"sm",	"sn",	"so",	"sp",
"sq",	"sr",	"ss",	"st",	"su",	"sv",	"sw",	"sx",	"sy",	"sz",
"ta",	"tb",	"tc",	"td",	"te",	"tf",	"tg",	"th",	"ti",	"tj",
"tk",	"tl",	"tm",	"tn",	"to",	"tp",	"tq",	"tr",	"ts",	"tt",
"tu",	"tv",	"tw",	"tx",	"ty",	"tz",	"ua",	"ub",	"uc",	"ud",
"ue",	"uf",	"ug",	"uh",	"ui",	"uj",	"uk",	"ul",	"um",	"un",
"uo",	"up",	"uq",	"ur",	"us",	"ut",	"uu",	"uv",	"uw",	"ux",
"uy",	"uz",	"va",	"vb",	"vc",	"vd",	"ve",	"vf",	"vg",	"vh",
"vi",	"vj",	"vk",	"vl",	"vm",	"vn",	"vo",	"vp",	"vq",	"vr",
"vs",	"vt",	"vu",	"vv",	"vw",	"vx",	"vy",	"vz",	"wa",	"wb",
"wc",	"wd",	"we",	"wf",	"wg",	"wh",	"wi",	"wj",	"wk",	"wl",
"wm",	"wn",	"wo",	"wp",	"wq",	"wr",	"ws",	"wt",	"wu",	"wv",
"ww",	"wx",	"wy",	"wz",	"xa",	"xb",	"xc",	"xd",	"xe",	"xf",
"xg",	"xh",	"xi",	"xj",	"xk",	"xl",	"xm",	"xn",	"xo",	"xp",
"xq",	"xr",	"xs",	"xt",	"xu",	"xv",	"xw",	"xx",	"xy",	"xz",
"ya",	"yb",	"yc",	"yd",	"ye",	"yf",	"yg",	"yh",	"yi",	"yj",
"yk",	"yl",	"ym",	"yn",	"yo",	"yp",	"yq",	"yr",	"ys",	"yt",
"yu",	"yv",	"yw",	"yx",	"yy",	"yz",	"za",	"zb",	"zc",	"zd",
"ze",	"zf",	"zg",	"zh",	"zi",	"zj",	"zk",	"zl",	"zm",	"zn",
"zo",	"zp",	"zq",	"zr",	"zs",	"zt",	"zu",	"zv",	"zw",	"zx",
"zy",	"zz",	"aaa",	"aab",	"aac",	"aad",	"aae",	"aaf",	"aag",	"aah",
"aai",	"aaj",	"aak",	"aal",	"aam",	"aan",	"aao",	"aap",	"aaq",	"aar",
"aas",	"aat",	"aau",	"aav",	"aaw",	"aax",	"aay",	"aaz",	"aba",	"abb",
"abc",	"abd",	"abe",	"abf",	"abg",	"abh",	"abi",	"abj",	"abk",	"abl",
"abm",	"abn",	"abo",	"abp",	"abq",	"abr",	"abs",	"abt",	"abu",	"abv",
"abw",	"abx",	"aby",	"abz",	"aca",	"acb",	"acc",	"acd",	"ace",	"acf",
"acg",	"ach",	"aci",	"acj",	"ack",	"acl",	"acm",	"acn",	"aco",	"acp",
"acq",	"acr",	"acs",	"act",	"acu",	"acv",	"acw",	"acx",	"acy",	"acz",
"ada",	"adb",	"adc",	"add",	"ade",	"adf",	"adg",	"adh",	"adi",	"adj",
"adk",	"adl",	"adm",	"adn",	"ado",	"adp",	"adq",	"adr",	"ads",	"adt",
"adu",	"adv",	"adw",	"adx",	"ady",	"adz",	"aea",	"aeb",	"aec",	"aed",
"aee",	"aef",	"aeg",	"aeh",	"aei",	"aej",	"aek",	"ael",	"aem",	"aen",
"aeo",	"aep",	"aeq",	"aer",	"aes",	"aet",	"aeu",	"aev",	"aew",	"aex",
"aey",	"aez",	"afa",	"afb",	"afc",	"afd",	"afe",	"aff",	"afg",	"afh",
"afi",	"afj",	"afk",	"afl",	"afm",	"afn",	"afo",	"afp",	"afq",	"afr",
"afs",	"aft",	"afu",	"afv",	"afw",	"afx",	"afy",	"afz",	"aga",	"agb",
"agc",	"agd",	"age",	"agf",	"agg",	"agh",	"agi",	"agj",	"agk",	"agl",
"agm",	"agn",	"ago",	"agp",	"agq",	"agr",	"ags",	"agt",	"agu",	"agv",
"agw",	"agx",	"agy",	"agz",	"aha",	"ahb",	"ahc",	"ahd",	"ahe",	"ahf",
"ahg",	"ahh",	"ahi",	"ahj",	"ahk",	"ahl",	"ahm",	"ahn",	"aho",	"ahp",
"ahq",	"ahr",	"ahs",	"aht",	"ahu",	"ahv",	"ahw",	"ahx",	"ahy",	"ahz",
"aia",	"aib",	"aic",	"aid",	"aie",	"aif",	"aig",	"aih",	"aii",	"aij",
"aik",	"ail",	"aim",	"ain",	"aio",	"aip",	"aiq",	"air",	"ais",	"ait",
"aiu",	"aiv",	"aiw",	"aix",	"aiy",	"aiz",	"aja",	"ajb",	"ajc",	"ajd",
"aje",	"ajf",	"ajg",	"ajh",	"aji",	"ajj",	"ajk",	"ajl",	"ajm",	"ajn",
"ajo",	"ajp",	"ajq",	"ajr",	"ajs",	"ajt",	"aju",	"ajv",	"ajw",	"ajx",
"ajy",	"ajz",	"aka",	"akb",	"akc",	"akd",	"ake",	"akf",	"akg",	"akh",
"aki",	"akj",	"akk",	"akl",	"akm",	"akn",	"ako",	"akp",	"akq",	"akr",
"aks",	"akt",	"aku",	"akv",	"akw",	"akx",	"aky",	"akz",	"ala",	"alb",
"alc",	"ald",	"ale",	"alf",	"alg",	"alh",	"ali",	"alj",	"alk",	"all",
};
