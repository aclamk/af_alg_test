

all: af_alg_perf

af_alg_perf: af_alg_perf.cpp
	g++ -std=c++11 $< -o $@
