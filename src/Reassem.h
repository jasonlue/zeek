// See the file "COPYING" in the main distribution directory for copyright.

#ifndef reassem_h
#define reassem_h

#include "Obj.h"
#include "IPAddr.h"

// Whenever subclassing the Reassembler class
// you should add to this for known subclasses.
enum ReassemblerType {
	REASSEM_UNKNOWN,
	REASSEM_TCP,
	REASSEM_FRAG,
	REASSEM_FILE,

	// Terminal value. Add new above.
	REASSEM_NUM,
};

class Reassembler;
class DataBlockList;

class DataBlock {
public:
	DataBlock(DataBlockList* list,
	          const u_char* data, uint64_t size, uint64_t seq,
	          DataBlock* prev, DataBlock* next);

	~DataBlock()	{ delete [] block; }

	uint64_t Size() const	{ return upper - seq; }

	DataBlock* next;	// next block with higher seq #
	DataBlock* prev;	// previous block with lower seq #
	uint64_t seq, upper;
	u_char* block;
};

// TODO: add comments
class DataBlockList {
public:

	DataBlockList()
		{ }

	DataBlockList(Reassembler* r) : reassembler(r)
		{ }

	~DataBlockList()
		{ Clear(); }

	const DataBlock* Head() const
		{ return head; }

	const DataBlock* Tail() const
		{ return tail; }

	bool Empty() const
		{ return head == nullptr; };

	size_t NumBlocks() const
		{ return total_blocks; };

	size_t DataSize() const
		{ return total_data_size; }

	void DataSize(uint64_t seq_cutoff, uint64_t* below, uint64_t* above) const;

	void Clear();

	DataBlock* Insert(uint64_t seq, uint64_t upper, const u_char* data,
	                  DataBlock* start = nullptr);

	void Append(DataBlock* block, uint64_t limit);

	uint64_t Trim(uint64_t seq, uint64_t max_old, DataBlockList* old_list);

private:

	void DeleteBlock(DataBlock* b);

	friend class DataBlock;

	Reassembler* reassembler = nullptr;
	DataBlock* head = nullptr;
	DataBlock* tail = nullptr;
	size_t total_blocks = 0;
	size_t total_data_size = 0;
};

class Reassembler : public BroObj {
public:
	Reassembler(uint64_t init_seq, ReassemblerType reassem_type = REASSEM_UNKNOWN);
	~Reassembler() override	{}

	void NewBlock(double t, uint64_t seq, uint64_t len, const u_char* data);

	// Throws away all blocks up to seq.  Returns number of bytes
	// if not all in-sequence, 0 if they were.
	uint64_t TrimToSeq(uint64_t seq);

	// Delete all held blocks.
	void ClearBlocks();
	void ClearOldBlocks();

	int HasBlocks() const
		{ return ! block_list.Empty(); }

	uint64_t LastReassemSeq() const	{ return last_reassem_seq; }

	uint64_t TrimSeq() const
		{ return trim_seq; }

	void SetTrimSeq(uint64_t seq)
		{ if ( seq > trim_seq ) trim_seq = seq; }

	uint64_t TotalSize() const;	// number of bytes buffered up

	void Describe(ODesc* d) const override;

	// Sum over all data buffered in some reassembler.
	static uint64_t TotalMemoryAllocation()	{ return total_size; }

	// Data buffered by type of reassembler.
	static uint64_t MemoryAllocation(ReassemblerType rtype);

	void SetMaxOldBlocks(uint32_t count)	{ max_old_blocks = count; }

protected:
	Reassembler()	{ }

	friend class DataBlock;
	friend class DataBlockList;

	virtual void Undelivered(uint64_t up_to_seq);

	virtual void BlockInserted(const DataBlock* b) = 0;
	virtual void Overlap(const u_char* b1, const u_char* b2, uint64_t n) = 0;

	void CheckOverlap(const DataBlockList& list,
				uint64_t seq, uint64_t len, const u_char* data);

	DataBlockList block_list;
	DataBlockList old_block_list;

	// TODO: maybe roll some of these stats into DataBlockList ?
	uint64_t last_reassem_seq;
	uint64_t trim_seq;	// how far we've trimmed
	uint32_t max_old_blocks;

	ReassemblerType rtype;

	static uint64_t total_size;
	static uint64_t sizes[REASSEM_NUM];
};

#endif
