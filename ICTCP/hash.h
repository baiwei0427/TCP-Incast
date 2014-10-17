#ifndef HASH_H
#define HASH_H

#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/vmalloc.h>
#include<linux/slab.h>

#include "flow.h"

#define HASH_RANGE 256	//The table has HASH_RANGE link lists
#define QUEUE_SIZE 32		    //Each link list contains QUEUE_SIZE nodes at most 


//Link Node of Flow
struct FlowNode{
	struct Flow f;                      //structure of Flow
	struct FlowNode* next; //pointer to next node 
};

//Link List of Flows
struct FlowList{
	struct FlowNode* head;  //pointer to head node of this link list
	int len;                                   //current length of this list (max: QUEUE_SIZE)
};

//Hash Table of Flows
struct FlowTable{
	struct FlowList* table;     //many FlowList (HASH_RANGE)
	int size;                                  //total number of nodes in this table
};

//Print a flow information
//Type: Add(0) Delete(1)
static void Print_Flow(struct Flow* f, int type)
{
	char local_ip[16]={0};           	//Local IP address 
	char remote_ip[16]={0};		    //Remote IP address 
	
	snprintf(local_ip, 16, "%pI4", &(f->local_ip));
	snprintf(remote_ip, 16, "%pI4", &(f->remote_ip));
	
	if(type==0)
	{
		printk(KERN_INFO "Insert a Flow record: %s:%hu to %s:%hu \n",local_ip,f->local_port,remote_ip,f->remote_port);
	}
	else if(type==1)
	{
		printk(KERN_INFO "Delete a Flow record: %s:%hu to %s:%hu \n",local_ip,f->local_port,remote_ip,f->remote_port);
	}
	else
	{
		printk(KERN_INFO "Flow record: %s:%hu to %s:%hu \n",local_ip,f->local_port,remote_ip,f->remote_port);
	}
}

//Hash function, calculate the flow should be inserted into which RuleList
static unsigned int Hash(struct Flow* f)
{
	//return a value in [0,HASH_RANGE-1]
	return ((f->local_ip/(256*256*256)+1)*(f->remote_ip/(256*256*256)+1)*(f->local_port+1)*(f->remote_port+1))%HASH_RANGE;
}

//Determine whether two Flows are equal 
//<local_ip, remote_ip, local_port, remote_port> determines a flow
static int Equal(struct Flow* f1,struct Flow* f2)
{
	return ((f1->local_ip==f2->local_ip)
	&&(f1->remote_ip==f2->remote_ip)
	&&(f1->local_port==f2->local_port)
	&&(f1->remote_port==f2->remote_port));		
}

//Initialize a Info structure
static void Init_Info(struct Info* i)
{
	i->srtt=0;	
	i->rwnd=0;	
	i->scale=1;
	i->phase=0;		
	i->size=0;
	i->throughput=0;
	i->last_update=0;
}

//Initialize a Flow structure
static void Init_Flow(struct Flow* f)
{
	f->local_ip=0;	
	f->remote_ip=0;
	f->local_port=0;
	f->remote_port=0;
	
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
	struct FlowNode* buf=NULL;
	//No node in current list
	fl->len=0;
	buf=vmalloc(sizeof(struct  FlowNode));
	if(!buf)
	{
		printk(KERN_INFO "Vmalloc error\n");
	}
	else
	{
		fl->head=buf;
		Init_Node(fl->head);
	}
}

//Initialize a FlowTable
static void Init_Table(struct FlowTable* ft)
{
	int i=0;
	struct FlowList* buf=NULL;
	
	//allocate space for RuleLists
	buf=vmalloc(HASH_RANGE*sizeof(struct FlowList));
	if(!buf)
	{
		printk(KERN_INFO "Vmalloc error\n");
	}
	else
	{
		ft->table=buf;
		//Initialize each FlowList
		for(i=0;i<HASH_RANGE;i++)
		{
			Init_List(&(ft->table[i]));
		}
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
		printk(KERN_INFO "No enough space in this link list\n");
		return 0;
	} 
	else 
	{
        struct FlowNode* tmp=fl->head;
		struct FlowNode* buf=NULL;

        //Come to the tail of this FlowList
        while(1)
        {
            if(tmp->next==NULL)//If pointer to next node is NULL, we find the tail of this FlowList. Here we can insert our new Flow
            {
				//Allocate memory
				buf=kmalloc(sizeof(struct FlowNode),GFP_ATOMIC);
				if(!buf) //Fail to allocate memory
				{
					printk(KERN_INFO "Kmalloc error\n");
					return 0;
				}
				else
				{
					tmp->next=buf;
					//Copy data for this new FlowNode
					tmp->next->f=*f;
					//Pointer to next FlowNode is NUll
					tmp->next->next=NULL;
					//Increase length of FlowList
					fl->len++;
					return 1;
				}
			}
            //If the rule of next node is the same as our inserted flow, we just finish the insert  
			else if(Equal(&(tmp->next->f),f)==1) 
			{
				printk(KERN_INFO "Equal Flow\n");
				return 0;
			}
            else //Move to next FlowNode
            {
				tmp=tmp->next;
            }
       }
	}
	return 0;
}

//Insert a flow to FlowTable
//If success, return 1. Else, return 0
static int Insert_Table(struct FlowTable* ft,struct Flow* f)
{
	int result=0;
	unsigned int index=Hash(f);
	
	//printk(KERN_INFO "Insert to link list %d\n",index);
	//Insert Flow to appropriate FlowList based on Hash value
	result=Insert_List(&(ft->table[index]),f);
	//Increase the size of FlowTable
	ft->size+=result;
	
	return result;
}

//Search the information for a given flow in a FlowList
//Note: we return the pointer to the structure of Info
//We can modify the information of this flow  
static struct Info* Search_List(struct FlowList* fl, struct Flow* f)
{
	//The length of FlowList is 0
	if(fl->len==0) 
	{
		return NULL;
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
				return NULL;
            }
			//Find matching flow (matching FlowNode is tmp->next rather than tmp)
			else if(Equal(&(tmp->next->f),f)==1)
			{
				//return the info of this Flow
				return &(tmp->next->f.i);
			}	
			else
			{
				//Move to next FlowNode
				tmp=tmp->next;
			}
		}
	}
	return NULL;
}

//Search the information for a given Flow in a FlowTable
static struct Info* Search_Table(struct FlowTable* ft, struct Flow* f)
{
	unsigned int index=0;
	index=Hash(f);
	return Search_List(&(ft->table[index]),f);
}

//Delete a Flow from FlowList
//If the Flow is deleted successfully, return rwnd of this flow (>0)
//Else, return 0
static unsigned int Delete_List(struct FlowList* fl, struct Flow* f)
{
	unsigned int result=0;
	
	//No node in current FlowList
	if(fl->len==0) 
	{
		//printk(KERN_INFO "No node in current list\n");
		return 0;
	}
	else 
	{
		struct FlowNode* tmp=fl->head;
		struct FlowNode* s=NULL;

		while(1)	
		{
			if(tmp->next==NULL) //If pointer to next node is NULL, we find the tail of this RuleList, no more RuleNodes, return 0
			{
				printk(KERN_INFO "There are %d flows in this list\n",fl->len);
				return 0;
			}
			else if(Equal(&(tmp->next->f),f)==1) //Find the matching rule (matching FlowNode is tmp->next rather than tmp), delete rule and return 1
			{
				//Get rwnd 
				result=tmp->next->f.i.rwnd;
				
				 s=tmp->next;
				//Print_Flow(&(tmp->next->f),2);
				
				tmp->next=s->next;
				//Delete matching FlowNode from this FlowList
				kfree(s);
				//Reduce the length of this FlowList by one
				fl->len--;
				//printk(KERN_INFO "Delete a flow record\n");
				return result;
			}
			else //Unmatch
			{
				//Move to next FlowNode
				tmp=tmp->next;
			}
		}
	}
	return 0;
}

//Delete a Flow from FlowTable
//If success, return rwnd (>0) of this entry. Else, return 0
static unsigned int Delete_Table(struct FlowTable* ft,struct Flow* f)
{
	unsigned int result=0;
	unsigned int index=0;
	index=Hash(f);
	//printk(KERN_INFO "Delete from link list %d\n",index);
	//Delete Flow from appropriate FlowList based on Hash value
	result=Delete_List(&(ft->table[index]),f);
	//Reduce the size of FlowTable by one
	if(result>0)
		ft->size-=1;
	//printk(KERN_INFO "Delete %d \n",result);
	return result;
}

//Clear a FlowList
static void Empty_List(struct FlowList* fl)
{
	struct FlowNode* NextNode;
	struct FlowNode* Ptr;
	for(Ptr=fl->head;Ptr!=NULL;Ptr=NextNode)
	{
		NextNode=Ptr->next;
		//Actually, we delete the fl->head in the first iteration
		//For fl->head, we use vfree. For other nodes, we use kfree
		if(Ptr==fl->head)
			vfree(Ptr);
		else
			kfree(Ptr);
	}
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

//Print a FlowNode
static void Print_Node(struct FlowNode* fn)
{
	Print_Flow(&(fn->f),2);
}

//Print a FlowList
static void Print_List(struct FlowList* fl)
{
	struct FlowNode* Ptr;
	for(Ptr=fl->head->next;Ptr!=NULL;Ptr=Ptr->next)
	{
		Print_Node(Ptr);
	}
}

//Print a FlowTable
static void Print_Table(struct FlowTable* ft)
{
	int i=0;
	printk(KERN_INFO "Current flow table:\n");
	for(i=0;i<HASH_RANGE;i++)
    {
		if(ft->table[i].len>0)
        {
			printk(KERN_INFO "FlowList %d\n",i);
			Print_List(&(ft->table[i]));
        }
    }
	printk(KERN_INFO "There are %d flows in total\n",ft->size);
}


#endif 