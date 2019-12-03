//load keys from file
//randomize it.
//1.insert to dictionary.
//2. remove 30% of keys.
//3. look ups
//test time used / insert, remove, looup existing item & failed lookup.
//test both OpenDict and ChainDict.
//Goal: see that OpenDict is consistently faster than ChainDict.
//If this is achieved, OpenDict has only a few tests to perform before it can replace ChainDict.
//Space with 1M SMB pcap packets, ChainDict: 367M; OpenDict: 81M, 22.5%.
#if 1//def USE_DICT_STATS

#include <vector>
#include <string>
#include <fstream>
#include <algorithm>
#include "time.h"
#include <sstream>
#include <iostream>
using namespace std;

#include "Dict.h"
#include "util.h"

#include <unordered_map>

class MeasureTime{
public:
    MeasureTime(std::string msg, long count=1 ): msg(msg), count(count){clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts1);}
    ~MeasureTime()
        {
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts2);
        long ns = (ts2.tv_sec - ts1.tv_sec) * 1000000000 + ts2.tv_nsec - ts1.tv_nsec;
		if( count > 0)
        	ns /= count;
		printf("%20s: %'ld nanoseconds.\n", msg.c_str(), ns);
        }

private:
    std::string msg;
    long count;
    timespec ts1, ts2;
};

class MeasureSpace{
    public:
        MeasureSpace(std::string msg, long count=1): msg(msg), count(count) 
        {
            uint64_t total;
            get_memory_usage(&total, &malloced);
        }
        ~MeasureSpace()
        {
            uint64_t total, malloced2 = 0;
            get_memory_usage(&total, &malloced2);
            uint64_t m = malloced2 - malloced;
            if(count > 0)
            {
                m /= count;
                printf("$20s: %'d bytes.\n", (int)m);
            }
        }

    private:
        std::string msg;
        long count;
        uint64_t malloced;
};

vector<Dictionary*> dicts;

bool DictLessThan(Dictionary* l, Dictionary* r)
    {
//	return l->Length() > r->Length();
#ifdef DICT_STATS_SORT_BY_DISTANCE
    int d1 = 0, d2 = 0;
    l->DistanceStats(d1);
    r->DistanceStats(d2);

	return d1 > d2; //reverse order by memory used.
#else
	return l->MemoryAllocation() > r->MemoryAllocation(); //reverse order by memory used.
#endif     
    }

vector<Dictionary*>& Dicts(int n_sorted)
    {
	auto nth = (int)dicts.size() > n_sorted ? dicts.begin() + n_sorted : dicts.end();
	nth_element(dicts.begin(), nth, dicts.end(), DictLessThan);
	sort(dicts.begin(), nth, DictLessThan);
	return dicts;
    }

void DictStats(string s, int largest_n)
    {
	auto dicts = Dicts(largest_n);
	int i=0;
	int empty = 0;
	int ordered = 0;
	int num_dicts[9];//track # of dicts with max length 0-7.
	memset(num_dicts, 0, sizeof(num_dicts));
	int num_entries = 0;
	int max_entries = 0;
	int capacity = 0;

	#define DICT_NUM_DISTANCES 5
	int distances[DICT_NUM_DISTANCES];
    int max_distance = 0;
    int distances_global[DICT_NUM_DISTANCES];
    memset(distances_global, 0, sizeof(int)*DICT_NUM_DISTANCES);
	int max_distance_global = 0;

	uint64_t memory = 0;
	printf("==============================================================%s=======================================================\n", s.c_str());
	for(auto d: dicts)
	    {
		empty += d->Length() ? 0 : 1;
		if( d->MaxLength() < 8)
			num_dicts[d->MaxLength()]++;
		else
			num_dicts[8]++;

		ordered += d->IsOrdered() ? 1 : 0;
    	d->DistanceStats(max_distance, distances, DICT_NUM_DISTANCES);
        for(int i=0; i<DICT_NUM_DISTANCES; i++)
            distances_global[i] += distances[i];

        if( max_distance_global < max_distance)
            max_distance_global = max_distance;
        
		num_entries += d->Length();
		max_entries += d->MaxLength();
		capacity += d->Capacity();
		memory += d->MemoryAllocation();
		if( ++i < largest_n )
			d->Dump(0);
		}	

	printf("----------------------------------------------------------------------------------------------------------------------\n");
	printf("    dicts: total %'d ordered %'d empty %'d ", (int)dicts.size(), ordered, empty);
	for(int i=0; i<8; i++)
		printf("[%d]%'d ", i, num_dicts[i]);
	printf("[8+]%'d\n", num_dicts[8]);

   	uint64_t total, malloced;
	get_memory_usage(&total, &malloced);
	printf("  entries: current %'d max %'d buckets %'d entries/dict %.2f buckets/dict %.2f load %.2f \n", 
		num_entries, max_entries, capacity, (float)num_entries/dicts.size(), (float)capacity/dicts.size(), (float)num_entries/capacity);

    if( num_entries > 0)
        {
        printf("distances: ");
        for(int i=0; i<DICT_NUM_DISTANCES-1; i++)
		    printf("[%d]%2d", i, 100*distances_global[i]/num_entries);
	    printf("[%d+]%2d\n", DICT_NUM_DISTANCES-1, 100*distances_global[DICT_NUM_DISTANCES-1]/num_entries);
        }
        else
            printf("\n");
        
    printf("     mem: dict %'luM total %'luM dict/total %.2f%% mem/dict %'3d mem/entry %'3d\n\n", 
        memory>>20, malloced>>20, (float)memory*100/malloced, int(memory/dicts.size()), (int)memory/(num_entries?num_entries:1));
    }

void DumpDictKeys( int top_n )
    {
	auto dicts = Dicts(top_n);

    int c = top_n;
    for( auto d : dicts)
        {
        if(c-- <= 0 )
            return;
        d->DumpKeys();
        }
    }


 bool LoadStringKeys(vector<string>& keys, string key_file)
    {
	fstream g(key_file, ios::in);
    string l;
    while(getline(g,l))
        keys.push_back(l);
    return true;
    }

 bool LoadStringHashKeys(vector<HashKey*>& keys, string key_file)
    {
 	fstream g(key_file, ios::in);
    string l;
    while(getline(g,l))
        keys.push_back(new HashKey(l.c_str(), l.length()));
    return true;
    }

bool LoadHashKeys(vector<HashKey*>& keys, string key_file)
    {
    vector<HashKey*> connections;
	fstream c(key_file, ios::in|ios::binary);
    int key_size;
    char key[4096];

    while( c.read((char*)&key_size, sizeof(int)) )
        {
        ASSERT(key_size < 4096);
        c.read(key, key_size);
        HashKey* hk = new HashKey(key,key_size);
        keys.push_back(hk);
        }
    return true;
    }

void LoadDict(PDict<char>& d, const vector<string>& keys)
    {
    //random_shuffle(keys.begin(), keys.end());
    for(auto k: keys)
        d.Insert(k.c_str(), new char[1]); //value not important, as long as they are different.
    }

void LoadDict( PDict<char>&  d, string key_file)
    {
    vector<string> keys;
    LoadStringKeys(keys, key_file);
    LoadDict(d,keys);
    }
   
void TestStringDictInsert(string key_file)
    {//use globalID dictionary keys.
    vector<string> keys;
    LoadStringKeys(keys, key_file);
    PDict<char> d;//(/*ORDERED*/);
    random_shuffle(keys.begin(), keys.end());
    for(int i=0; i<(int)keys.size(); i++)
        {
        d.Insert(keys[i].c_str(), new char[1]);
        vector<string >iterKeys;
        IterCookie* c = d.InitForIteration();
        void* v;
        HashKey* hk;
        while((v=d.NextEntry(hk,c)))
            iterKeys.push_back(string((char*)hk->Key(), hk->Size()));
        ASSERT((int)iterKeys.size() == i+1);
        sort(iterKeys.begin(), iterKeys.end());
        sort(keys.begin(), keys.begin()+i+1);
        for(int j=0; j<=i; j++)
            ASSERT(keys[j] == iterKeys[j]);
        }
    d.Dump();
    }

void StringDictPerf2(string cmd, string key_file, int num_keys, int rounds)
    {
    char* value = new char[1];
    vector<HashKey*> keys;
    LoadStringHashKeys(keys, key_file);
    int items = (int)keys.size();
    if( num_keys < 0)
        num_keys = items;
    else if( num_keys > items)
        num_keys = items;
    cout <<  "\n" << cmd << " dict " << key_file << " size: " << num_keys << " rounds: " << rounds << endl;
    PDict<char> d0;
    for(int j = 0; j < num_keys; j++)
        d0.Insert(keys[j], value);
    d0.Dump();

    uint64_t total = 0, malloced = 0, malloced2 = 0;
    get_memory_usage(&total, &malloced);
   PDict<char>* d = new PDict<char>[rounds];//(/*UNORDERED*/);

    random_shuffle(keys.begin(), keys.end());
    {
        MeasureTime m("Insert", rounds*num_keys);
        for(int i = 0; i < rounds; i++)
            for(int j = 0; j < num_keys; j++)
                d[i].Insert(keys[j], value);
    }
    get_memory_usage(&total, &malloced2);
    cout << "memory/entry: " << (malloced2 - malloced)/rounds/num_keys << endl;
    random_shuffle(keys.begin(), keys.end());
    {
        MeasureTime m("Successful Lookup", rounds*num_keys);
        for(int i = 0; i < rounds; i++)
            for(int j = 0; j < num_keys; j++)
                d[i].Lookup(keys[j]);
    }

    vector<HashKey*> lower_keys;
    char key[4096];
    for(auto hk:keys)
        {
        for(int j = 0; j < (int)hk->Size(); j++)
            {
            const char* k = (const char*)hk->Key();
            key[j] = tolower(k[j]);
            }
        lower_keys.push_back(new HashKey(key, hk->Size()));
        }

    {
        MeasureTime m("Unsuccessful Lookup", rounds*num_keys);
        for(int i=0; i<rounds; i++)
            for(int j = 0; j < num_keys; j++)
                d[i].Lookup(lower_keys[j]);
    }

    random_shuffle(keys.begin(), keys.end());
    {
        MeasureTime m("Remove", rounds*num_keys);
        for(int i=0; i<rounds; i++)
            for(int j = 0; j < num_keys; j++)
                d[i].RemoveEntry(keys[j]);
    }
    delete []d;
    }

void StringDictPerf(string cmd, string key_file, int num_keys, int rounds)
    {
    char* value = new char[1];
    vector<string> keys;
    LoadStringKeys(keys, key_file);
    int items = (int)keys.size();
    if( num_keys < 0)
        num_keys = items;
    else if( num_keys > items)
        num_keys = items;
    cout <<  "\n" << cmd << " dict " << key_file << " size: " << num_keys << " rounds: " << rounds << endl;

    uint64_t total = 0, malloced = 0, malloced2 = 0;
    get_memory_usage(&total, &malloced);
   PDict<char>* d = new PDict<char>[rounds];//(/*UNORDERED*/);

    random_shuffle(keys.begin(), keys.end());
    {
        MeasureTime m("Insert", rounds*num_keys);
        for(int i = 0; i < rounds; i++)
            for(int j = 0; j < num_keys; j++)
                d[i].Insert(keys[j].c_str(), value);
    }
    get_memory_usage(&total, &malloced2);
    cout << "memory/entry: " << (malloced2 - malloced)/rounds/num_keys << endl;
    //d[0].Dump();
    random_shuffle(keys.begin(), keys.end());
    {
        MeasureTime m("Successful Lookup", rounds*num_keys);
        for(int i = 0; i < rounds; i++)
            for(int j = 0; j < num_keys; j++)
                d[i].Lookup(keys[j].c_str());
    }

    for(int i=0; i<(int)keys.size(); i++)
        for(int j = 0; j< (int)keys[i].size(); j++)
            keys[i][j] = tolower(keys[i][j]);

    {
        MeasureTime m("Unsuccessful Lookup", rounds*num_keys);
        for(int i=0; i<rounds; i++)
            for(int j = 0; j < num_keys; j++)
                d[i].Lookup(keys[j].c_str());
    }

    random_shuffle(keys.begin(), keys.end());
    {
        MeasureTime m("Remove", rounds*num_keys);
        for(int i=0; i<rounds; i++)
            {
            for(int j = 0; j < num_keys; j++)
                {
                HashKey hk(keys[j].c_str());
                d[i].RemoveEntry(&hk);
                }
            }
    }
    delete []d;
    }

struct Hasher
    {
    std::size_t operator()(string const& k) const
        {
        return HashKey::HashBytes(k.c_str(), k.length());
        }
    };

void StringMapPerf(string cmd, string key_file, int num_keys, int rounds)
    {
    char* value = new char[1];
    vector<string> keys;
    LoadStringKeys(keys, key_file);
    int items = (int)keys.size();
    if( num_keys < 0)
        num_keys = items;
    else if( num_keys > items)
        num_keys = items;
    cout <<  "\n" << cmd << " unordered map " << key_file << " size: " << num_keys << " rounds: " << rounds << endl;

    uint64_t total = 0, malloced = 0, malloced2 = 0;
    get_memory_usage(&total, &malloced);
    unordered_map<string, char*, Hasher>* d = new unordered_map<string, char*, Hasher>[rounds];
    random_shuffle(keys.begin(), keys.end());
    {
        MeasureTime m("Insert", rounds*num_keys);
        for(int i = 0; i < rounds; i++)
            for(int j = 0; j < num_keys; j++)
                d[i].emplace(keys[j], new char[1]);
    }
    get_memory_usage(&total, &malloced2);
    cout << "memory/entry: " << (malloced2 - malloced)/rounds/num_keys << endl;
    random_shuffle(keys.begin(), keys.end());
    {
        MeasureTime m("Successful Lookup", rounds*num_keys);
        for(int i = 0; i < rounds; i++)
            for(int j = 0; j < num_keys; j++)
                d[i].find(keys[j]);
    }

    for(int i=0; i<(int)keys.size(); i++)
    {
    char* value = new char[1];
    vector<string> keys;
    LoadStringKeys(keys, key_file);
    int items = (int)keys.size();
    if( num_keys < 0)
        num_keys = items;
    else if( num_keys > items)
        num_keys = items;
    cout <<  "\n" << cmd << " unordered map " << key_file << " size: " << num_keys << " rounds: " << rounds << endl;

    uint64_t total = 0, malloced = 0, malloced2 = 0;
    get_memory_usage(&total, &malloced);
    unordered_map<string, char*>* d = new unordered_map<string, char*>[rounds];
    random_shuffle(keys.begin(), keys.end());
    {
        MeasureTime m("Insert", rounds*num_keys);
        for(int i = 0; i < rounds; i++)
            for(int j = 0; j < num_keys; j++)
                d[i].emplace(keys[j], new char[1]);
    }
    get_memory_usage(&total, &malloced2);
    cout << "memory/entry: " << (malloced2 - malloced)/rounds/num_keys << endl;
    random_shuffle(keys.begin(), keys.end());
    {
        MeasureTime m("Successful Lookup", rounds*num_keys);
        for(int i = 0; i < rounds; i++)
            for(int j = 0; j < num_keys; j++)
                d[i].find(keys[j]);
    }

    for(int i=0; i<(int)keys.size(); i++)
        for(int j = 0; j< (int)keys[i].size(); j++)
            keys[i][j] = tolower(keys[i][j]);

    {
        MeasureTime m("Unsuccessful Lookup", rounds*num_keys);
        for(int i=0; i<rounds; i++)
            for(int j = 0; j < num_keys; j++)
                d[i].find(keys[j]);
    }

    random_shuffle(keys.begin(), keys.end());
    {
        MeasureTime m("Remove", rounds*num_keys);
        for(int i=0; i<rounds; i++)
            {
            for(int j = 0; j < num_keys; j++)
                d[i].erase(keys[i]);
            }
    }
    delete []d;
    }

    {
        MeasureTime m("Unsuccessful Lookup", rounds*num_keys);
        for(int i=0; i<rounds; i++)
            for(int j = 0; j < num_keys; j++)
                d[i].find(keys[j]);
    }

    random_shuffle(keys.begin(), keys.end());
    {
        MeasureTime m("Remove", rounds*num_keys);
        for(int i=0; i<rounds; i++)
            {
            for(int j = 0; j < num_keys; j++)
                d[i].erase(keys[i]);
            }
    }
    delete []d;
    }

void StringMapPerf2(string cmd, string key_file, int num_keys, int rounds)
    {
    char* value = new char[1];
    vector<string> keys;
    LoadStringKeys(keys, key_file);
    int items = (int)keys.size();
    if( num_keys < 0)
        num_keys = items;
    else if( num_keys > items)
        num_keys = items;
    cout <<  "\n" << cmd << " unordered map " << key_file << " size: " << num_keys << " rounds: " << rounds << endl;

    uint64_t total = 0, malloced = 0, malloced2 = 0;
    get_memory_usage(&total, &malloced);
    unordered_map<string, char*>* d = new unordered_map<string, char*>[rounds];
    random_shuffle(keys.begin(), keys.end());
    {
        MeasureTime m("Insert", rounds*num_keys);
        for(int i = 0; i < rounds; i++)
            for(int j = 0; j < num_keys; j++)
                d[i].emplace(keys[j], new char[1]);
    }
    get_memory_usage(&total, &malloced2);
    cout << "memory/entry: " << (malloced2 - malloced)/rounds/num_keys << endl;
    random_shuffle(keys.begin(), keys.end());
    {
        MeasureTime m("Successful Lookup", rounds*num_keys);
        for(int i = 0; i < rounds; i++)
            for(int j = 0; j < num_keys; j++)
                d[i].find(keys[j]);
    }

    for(int i=0; i<(int)keys.size(); i++)
        for(int j = 0; j< (int)keys[i].size(); j++)
            keys[i][j] = tolower(keys[i][j]);

    {
        MeasureTime m("Unsuccessful Lookup", rounds*num_keys);
        for(int i=0; i<rounds; i++)
            for(int j = 0; j < num_keys; j++)
                d[i].find(keys[j]);
    }

    random_shuffle(keys.begin(), keys.end());
    {
        MeasureTime m("Remove", rounds*num_keys);
        for(int i=0; i<rounds; i++)
            {
            for(int j = 0; j < num_keys; j++)
                d[i].erase(keys[i]);
            }
    }
    delete []d;
    }

void unordered(int size, int rounds)
	{
	fprintf(stderr, "std::unordered_map\n");
	std::unordered_map<int, int*> m;
    int* keys = new int[size]; 
    for(int i=0; i<size; i++)
        keys[i] = i;
    random_shuffle(&keys[0], &keys[size]);
	int* val = new int(1);

	struct timespec ts;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
	uint64_t last = (ts.tv_sec * 1000000000) + ts.tv_nsec;
	for (int i = 0; i < size; i++ )
		m.emplace(keys[i], new int(keys[i]));

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    uint64_t now = (ts.tv_sec * 1000000000) + ts.tv_nsec;
    printf("%d,%llu\n", size, (now-last)/size);
    delete []keys;
	}

void dict(int size, int rounds)
	{
	fprintf(stderr, "dict\n");
	PDict<int> d;
    int* keys = new int[size]; 
    for(int i=0; i<size; i++)
        keys[i] = i;
    random_shuffle(&keys[0], &keys[size]);

	struct timespec ts;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
	uint64_t last = (ts.tv_sec * 1000000000) + ts.tv_nsec;
	for ( int i = 0; i < size; i++ )
    {
		HashKey* h = new HashKey(bro_int_t(i));
		d.Insert(h, new int(i));        
    }
    //d.Insert(&keys[i], sizeof(int), std::hash<int>()(keys[i]), new int(keys[i]), 1);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    uint64_t now = (ts.tv_sec * 1000000000) + ts.tv_nsec;
    printf("%d,%llu\n", size, (now-last)/size);
    delete []keys;
	}

void BinaryDictPerf(string cmd, string key_file, int num_keys, int rounds)
    {
    char* value = new char[1];
    vector<HashKey*> connections;
    LoadHashKeys(connections, key_file);
    int items = connections.size();
    if( num_keys < 0)
        num_keys = items;
    else if( num_keys > items)
        num_keys = items;
    cout <<  "\n" << cmd << " " << key_file << " size: " << num_keys << " rounds: " << rounds << endl;
    PDict<char> d0;
    for(int j = 0; j < num_keys; j++)
        d0.Insert(connections[j], value);
    d0.Dump();
    PDict<char>* d = new PDict<char>[rounds];

    {
        MeasureSpace space("dict", rounds*num_keys);
        random_shuffle(connections.begin(), connections.end());
        {
            MeasureTime m("Insert", rounds*num_keys);
            for(int i = 0; i < rounds; i++)
                for(int j = 0; j < num_keys; j++)
                    d[i].Insert(connections[j], value);
        }
    }

    random_shuffle(connections.begin(), connections.end());
    {
        MeasureTime m("Successful Lookup", rounds*num_keys);
        for(int i = 0; i < rounds; i++)
            for( int j = 0; j < num_keys; j++ )
                d[i].Lookup(connections[j]);
    }

    vector<HashKey*> xor_connections;
    char key[4096];
    for(auto c: connections)
        {
        for(int j = 0; j < (int)c->Size(); j++)
            {
            const char* k = (const char*)c->Key();
            key[j] = k[j] ^ 0xFF;
            }
        xor_connections.push_back(new HashKey(key, c->Size()));
        }

    {
        MeasureTime m("Unsuccessful Lookup", rounds*num_keys);
        for(int i = 0; i < rounds; i++)
            for(int j = 0; j < num_keys; j++ )
                d[i].Lookup(xor_connections[j]);
    }

    random_shuffle(connections.begin(), connections.end());
    {
        MeasureTime m("Remove", rounds*num_keys);
        for(int i = 0; i < rounds; i++)
            for( int j = 0; j < num_keys; j++)
                d[i].RemoveEntry(connections[j]);
    }
    delete []d;
    }

void TestLookupDuringIterationWhileRemapping(string key_file)
    {//remove every key iterated. to simulate dictionary item expiry function.
    vector<string> keys;
    LoadStringKeys(keys, key_file);
    random_shuffle(keys.begin(), keys.end());

    PDict<char> d;
    LoadDict(d, keys);

    vector<string> iterKeys;

    //iterate & e
    IterCookie* c = d.InitForIteration();
    //should be good for non-rebust cookies.
    //d.MakeRobustCookie(c);
    char* v;
    HashKey*  hk;
    while( (v = d.NextEntry(hk, c) ))
        {
        iterKeys.push_back(string((char*)hk->Key(), hk->Size()));
        char* v2 = d.Lookup(hk);
        ASSERT(v == v2);
        }
    //now iterKeys should be the same as keys.
    sort(keys.begin(), keys.end());
    sort(iterKeys.begin(), iterKeys.end());
    ASSERT(keys.size() == iterKeys.size());
    for(int i=0; i<(int)keys.size(); i++)
        ASSERT(keys[i] == iterKeys[i]);
    }

void TestRemoveDuringIteration(string key_file)
    {//remove every key iterated. to simulate dictionary item expiry function.
    vector<string> keys;
    LoadStringKeys(keys, key_file);
    random_shuffle(keys.begin(), keys.end());

    PDict<char> d;
    LoadDict(d, keys);

    vector<string> iterKeys;

    //iterate & e
    IterCookie* c = d.InitForIteration();
    d.MakeRobustCookie(c);
    char* v;
    HashKey*  hk;
    while( (v = d.NextEntry(hk, c) ))
        {
        iterKeys.push_back(string((char*)hk->Key(), hk->Size()));
        d.Remove(hk);
        }
    //now iterKeys should be the same as keys.
    sort(keys.begin(), keys.end());
    sort(iterKeys.begin(), iterKeys.end());
    ASSERT(keys.size() == iterKeys.size());
    for(int i=0; i<(int)keys.size(); i++)
        ASSERT(keys[i] == iterKeys[i]);
    }

void TestInsertRemapDuringIteration(string key_file)
    {//have safe iteration pending, then insert remove before on and after.
    vector<string> keys;
    LoadStringKeys(keys, key_file);
    sort(keys.begin(), keys.end());
    char* value = new char[1];
    *value = 'v';
    PDict<char> d;

    vector<string> iterKeys;

    //iterate & insert
    IterCookie* c = d.InitForIteration();
    d.MakeRobustCookie(c);
    char* v;
    HashKey*  hk;
    for(int i=0; i<(int)keys.size(); i++)
        {
        d.Insert(keys[i].c_str(), value);
        v = d.NextEntry(hk, c);
        ASSERT(v != NULL );
        iterKeys.push_back(string((char*)hk->Key(), hk->Size()));
        } 
    //now iterKeys should be the same as keys.
    sort(iterKeys.begin(), iterKeys.end());
    ASSERT(keys.size() == iterKeys.size());
    for(int i=0; i<(int)keys.size(); i++)
        ASSERT(keys[i] == iterKeys[i]);
    }

void TestInsertDuringIteration(string key_file)
    {//have safe iteration pending, then insert remove before on and after.
    vector<string> keys;
    LoadStringKeys(keys, key_file);
    random_shuffle(keys.begin(), keys.end());
    int m = keys.size()/2;
    char* value = new char[1];
    *value = 'v';
    PDict<char> d;
    int i=keys.size()-1;
    for(; i>=m; i--)
        d.Insert(keys[i].c_str(), value);

    //insert half of the keys into dictionary, then while iteerating, insert one at one iteration.
    vector<string> iterKeys;

    //iterate & e
    IterCookie* c = d.InitForIteration();
    d.MakeRobustCookie(c);
    char* v;
    HashKey*  hk;
    while( (v = d.NextEntry(hk, c) ))
        {
        iterKeys.push_back(string((char*)hk->Key(), hk->Size()));
        if(i>=0)
            d.Insert(keys[i--].c_str(), value);
        }
    //now iterKeys should be the same as keys.
    sort(keys.begin(), keys.end());
    sort(iterKeys.begin(), iterKeys.end());
    ASSERT(keys.size() == iterKeys.size());
    for(int i=0; i<(int)keys.size(); i++)
        ASSERT(keys[i] == iterKeys[i]);
    }

bool HasSuffix(string full, string suffix)
    {
    if( full.length() < suffix.length())
        return false;
    return 0 == full.compare(full.length() - suffix.length(), suffix.length(), suffix);
    }

void TestDictMain(string cmd, string param)
    {//key_file@size:rounds
    istringstream p(param);
    string key_file, s, r;
    int size = 100;
    int rounds = 10;
    getline(p, key_file, '@');
    if( getline(p, s, ':'))
    {
        getline(p, r);
    }

    if( !r.empty())
        rounds = stoi(r);
    if( !s.empty() )
        size = stoi(s);

//    dict(size, rounds);
    //getchar();
 //   unordered(size, rounds);
  //  return;
    if( HasSuffix(key_file, ".ckey") )
    {
        StringDictPerf(cmd, key_file, size, rounds);
        StringMapPerf(cmd, key_file, size, rounds);
    }
    else
        BinaryDictPerf(cmd, key_file, size, rounds);
    //TestLookupDuringIterationWhileRemapping(key_file);
    //TestStringDictInsert(key_file);
    //TestInsertRemapDuringIteration(key_file);
    //TestRemoveDuringIteration(key_file);
    //TestInsertDuringIteration(key_file);
    }


#endif//USE_DICT_STATS
