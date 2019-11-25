#ifndef DictStats_h
#define DictStats_h
#include <string>

#ifdef USE_DICT_STATS

void TestDictMain(std::string cmd, std::string key_file);

#ifndef DICT_STATS_TOP
#define DICT_STATS_TOP 10
#endif//DICT_STATS_TOP

void  DumpDictKeys(int top_n=DICT_STATS_TOP);
void DictStats(std::string s="", int top_n=DICT_STATS_TOP);
#define DICT_STATS DictStats 

#else

#define DICT_STATS() 

#endif//USE_DICT_STATS

#endif//DictStats_h