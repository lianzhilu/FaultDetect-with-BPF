#include<iostream>
#include<ctime>
using namespace std;
int main()
{
	time_t begin;
	begin = time(NULL);
	cout<<begin;

	while(true)
	{
		int* a=new int[1024];
    	for(int i=0;i<1024;i++)
			a[i]=1;

		time_t delta=time(NULL)-begin;
		cout<<delta<<endl;
		if(delta>=2500)
			return 0;
		
	}
}
