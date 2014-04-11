#ifndef HASH_H
#define HASH_H

#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/vmalloc.h>

#include "flow.h"

#define HASH_RANGE 256	//Be default, we have HASH_RANGE link lists
#define QUEUE_SIZE 32	//Be default, each link list contains QUEUE_SIZE nodes at most 


//Link Node of Flow
struct FlowNode{
	struct Flow f;         //structure of Flow
	struct FlowNode* next; //pointer to next node 
};

//Link List of Flows
struct FlowList{
	struct FlowNode* head; //pointer to head node of this link list
	int len;               //current length of this list (max: QUEUE_SIZE)
};

//Hash Table of Flows
struct FlowTable{
	struct FlowList* table; //many FlowList (HASH_RANGE)
	int size;               //total number of nodes in this table
};

//Hash function, calculate the flow should be inserted into which RuleList
static unsigned int Hash(struct Flow* f)
{
	//<src_ip, dst_ip, src_port, dst_port> identifies a flow
	return (f->src_ip/(256*256*256)+1)*(f->dst_ip/(256*256*256)+1)*(f->src_port+1)*(f->dst_port+1)%HASH_RANGE;
}

//Determine whether two Flows are equal 
//<src_ip, dst_ip, src_port, dst_port> identifies a flow 
static int Equal(struct Flow* f1,struct Flow* f2)
{
	return (f1->src_ip==f2->src_ip)&&(f1->dst_ip==f2->dst_ip)&&(f1->src_port==f2->src_port)&&(f1->dst_port==f2->dst_port);
}

//Initialize a Info structure
static void Init_Info(struct Info* i)
{
	i->ack_bytes=0;		
	i->srtt=0;	
	i->rwnd=0;	
	i->prio=1;			
	i->phase=1;			
}

//Initialize a Flow structure
static void Init_Flow(struct Flow* f)
{
	f->src_ip=0;	
	f->dst_ip=0;
	f->src_port=0;
	f->dst_port=0;
	
	//Initialize the Info of this Flow
	Init_Info(&(f->i));
	
}

//Initialize a FlowNode
static void Init_Node(struct FlowNode* fn)
{
	//Initialize next pointer as null
	fn->next=NULL;
	//Initialize a flow structure
	Init_Flow(&(fn->f));
}

//Initialize a FlowList
static void Init_List(struct FlowList* fl)
{
	//Only a head node in current list
	fl->len=0;
	fl->head=vmalloc(sizeof(struct FlowNode));
	Init_Node(fl->head);
}

//Initialize a FlowTable
static void Init_Table(struct FlowTable* ft)
{
	int i=0;
	//allocate space for RuleLists
	ft->table=vmalloc(HASH_RANGE*sizeof(struct FlowList));
		
	//Initialize Flow Lists
	for(i=0;i<HASH_RANGE;i++)
	{
		//Initialize each FlowList
		Init_List(&(ft->table[i]));
	}
	
	//No nodes in current table
	ft->size=0;
}

//Insert a Flow into a FlowList
//If the new flow is inserted successfully, return 1
//Else (e.g. fl->len>=QUEUE_SIZE or the same flow exists), return 0
static int Insert_List(struct FlowList* fl, struct Flow* f)
{
	if(fl->len>=QUEUE_SIZE) 
	{
		return 0;
	} 
	else 
	{
        struct FlowNode* tmp=fl->head;

        //Come to the tail of this FlowList
        while(1)
        {
			//If pointer to next node is NULL, we find the tail of this FlowList. Here we can insert our new Flow
            if(tmp->next==NULL)
            {
                tmp->next=vmalloc(sizeof(struct FlowNode));
                //Copy data for this new FlowNode
                tmp->next->f=*f;
                //Pointer to next FlowNode is NUll
                tmp->next->next=NULL;
				//Increase length of FlowList
                fl->len++;
                //Finish the insert
                return 1;
			}
			//If the rule of next node is the same as our inserted flow, we just finish the insert  
			else if(Equal(&(tmp->next->f),f))
			{
				return 0;
			}
			//Move to next FlowNode
            else
            {
				tmp=tmp->next;
            }
       }
	}
	return 0;
}

//Insert a flow to FlowTable
static void Insert_Table(struct FlowTable* ft,struct Flow* f)
{
	int result=0;
	unsigned int index=Hash(f);
		
	//Insert Flow to appropriate FlowList based on Hash value
	result=Insert_List(&(ft->table[index]),f);
	//Increase the size of FlowTable
	ft->size+=result;
}

//Search the information for a given flow in a FlowList
//Note: we return the pointer to the structure of Info
//We can modify the information of this flow  
static struct Info* Search_List(struct FlowList* fl, struct Flow* f)
{
	struct Info* info_pointer;
	Init_Info(info_pointer);

	//The length of FlowList is 0
	if(fl->len==0) 
	{
		return info_pointer;
	} 
	else 
	{
		struct FlowNode* tmp=fl->head;
		//Find the Flow in this FlowList
		while(1)
		{
			//If pointer to next node is NULL, we find the tail of this FlowList, no more FlowNodes to search
			if(tmp->next==NULL)
			{
				return info_pointer;
            }
			//Find matching flow (matching FlowNode is tmp->next rather than tmp)
			if(Equal(&(tmp->next->f),f))
			{
				//Move the pointer
				info_pointer=&(tmp->next->f.i);
			
				//return the info of this Flow
				return info_pointer;
			}	
			else
			{
				//Move to next FlowNode
				tmp=tmp->next;
			}
		}
	}
	return info_pointer;
}

//Search the information for a given Flow in a FlowTable
static struct Info* Search_Table(struct FlowTable* ft, struct Flow* f)
{
	unsigned int index=0;
	index=Hash(f);
	return Search_List(&(ft->table[index]),f);
}

//Delete a Flow from FlowList
//If the Flow is deleted successfully, return 1
//Else, return 0
static int Delete_List(struct FlowList* fl, struct Flow* f)
{
	//No node in current FlowList
	if(fl->len==0) 
	{
		return 0;
	}
	else 
	{
		struct FlowNode* tmp=fl->head;

		while(1)	
		{
			//If pointer to next node is NULL, we find the tail of this RuleList, no more RuleNodes, return 0
			if(tmp->next==NULL)
			{
				return 0;
			}
			//Find the matching rule (matching FlowNode is tmp->next rather than tmp), delete rule and return 1
			if(Equal(&(tmp->next->f),f))
			{
				struct FlowNode* s=tmp->next;
				tmp->next=s->next;
				//Delete matching FlowNode from this FlowList
				vfree(s);
				//Reduce the length of this FlowList by one
				fl->len--;
				return 1;
			}
			else
			{
				//Move to next FlowNode
				tmp=tmp->next;
			}
		}
	}
	return 0;
}

//Delete a Flow from FlowTable
static void Delete_Table(struct FlowTable* ft,struct Flow* f)
{
	int result=0;
	unsigned int index=0;
	index=Hash(f);
	//Delete Flow from appropriate FlowList based on Hash value
	result=Delete_List(&(ft->table[index]),f);
	//Reduce the size of FlowTable by one
	ft->size-=result;
}

//Clear a FlowList
static void Empty_List(struct FlowList* fl)
{
	struct FlowNode* NextNode;
	struct FlowNode* Ptr;
	for(Ptr=fl->head;Ptr!=NULL;Ptr=NextNode)
	{
		NextNode=Ptr->next;
		vfree(Ptr);
	}
	//vfree(rl->head);
	//rl->head=NULL;
}

//Clear a FlowTable
static void Empty_Table(struct FlowTable* ft)
{
	int i=0;
	for(i=0;i<HASH_RANGE;i++)
	{
		Empty_List(&(ft->table[i]));
	}
	vfree(ft->table);
}


#endif 