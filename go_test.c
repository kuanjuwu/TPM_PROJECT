#include "common.h"
int nv_search(int, int);
int nv_max_hit(int);
int nv_define(int);
int nv_stress(BYTE[], int);

int main(void)
{  
	int nv_max;

	int max=100;
	
	while(nv_define(max)==0)
	{	
		max*=2;
	}

	nv_max = nv_search(1, max);

	printf("\tMaximum TPM NV SIZE = %d Bytes\n", nv_max);
	
	BYTE* data2write = (BYTE*) malloc(nv_max);
	
	if (data2write==NULL){
		fprintf(stderr,"NULL PTR\n");
		exit(1);
	}

	nv_stress(data2write, nv_max);

	free(data2write);
	
	data2write=NULL;

}

/* Search for max NV size */
int nv_search(int lo, int hi)
{
	static int i = 0;
	
	printf("Counter=%d, lo=%ld, hi=%ld\n", ++i, lo, hi);
	
	int mid = lo+(hi-lo)/2;
	
	if(nv_max_hit(mid)==0)
		return mid;

	else if(nv_define(mid)==0)
		nv_search(mid, hi);

	else
		nv_search(lo, mid);	
}

/* Return 0 when we find the max NV size */
int nv_max_hit(int i)
{
	if (nv_define(i)==0 && nv_define(i+1)!=0)
		return 0;
	else 
		return 1;
}

/* Define NV space */
int nv_define(int i)
{
	char         *nameOfFunction    = "TPM_NV_DefineSpace";
        
        TSS_HCONTEXT hContext           = NULL_HCONTEXT;
        TSS_HNVSTORE hNVStore           = 0;//NULL_HNVSTORE
        TSS_HOBJECT  hPolObject         = NULL_HOBJECT;
        TSS_HPOLICY  hPolicy            = NULL_HPOLICY;
        TSS_HTPM     hTPM               = NULL_HTPM;
        BYTE         *auth              = "123456";
        UINT32       auth_length        = 6;
        TSS_RESULT   result;


	BYTE* data = (BYTE*) malloc(i);
	memset(data, 'a', i);

        print_begin_test(nameOfFunction);

	/* Create Context */
	result = Tspi_Context_Create(&hContext);
        if (result != TSS_SUCCESS) {
                print_error("Tspi_Context_Create ", result);
                print_error_exit(nameOfFunction, err_string(result));
                exit(result);
        }

	/* Connect Context */
	result = Tspi_Context_Connect(hContext,NULL);
        if (result != TSS_SUCCESS) {
                print_error("Tspi_Context_Connect", result);
                print_error_exit(nameOfFunction, err_string(result));
                Tspi_Context_FreeMemory(hContext, NULL);               
                Tspi_Context_Close(hContext);
                exit(result);
        }

	/* Create TPM NV Object */
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0,&hNVStore);
        if (result != TSS_SUCCESS)
        {
                print_error("Tspi_Context_CreateObject", result);
                print_error_exit(nameOfFunction, err_string(result));
                Tspi_Context_FreeMemory(hContext, NULL);
                Tspi_Context_Close(hContext);
                exit(result);
        }

	/* Get TPM Object */
	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
        if (result != TSS_SUCCESS)
        {
                print_error("Tspi_Context_GetTpmObject", result);
                print_error_exit(nameOfFunction, err_string(result));
                Tspi_Context_FreeMemory(hContext, NULL);
                Tspi_Context_Close(hContext);
                exit(result);
        }

	result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hPolicy);
        if (result != TSS_SUCCESS)
        {
                print_error("Tspi_GetPolicyObject", result);
                print_error_exit(nameOfFunction, err_string(result));
                Tspi_Context_FreeMemory(hContext, NULL);
                Tspi_Context_Close(hContext);
                exit(result);
        }

	/* Set Password */
	result = Tspi_Policy_SetSecret(hPolicy, TESTSUITE_OWNER_SECRET_MODE,
                                        TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);

        if (result != TSS_SUCCESS)
        {
                print_error("Tspi_Policy_SetSecret", result);
                print_error_exit(nameOfFunction, err_string(result));
                Tspi_Context_FreeMemory(hContext, NULL);
                Tspi_Context_Close(hContext);
                exit(result);
        }
	
	// Create policy object for the NV object
        result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hPolObject);
        if (result != TSS_SUCCESS)
        {
                 print_error("Tspi_Context_CreateObject", result);
                 print_error_exit(nameOfFunction, err_string(result));
                 Tspi_Context_FreeMemory(hContext, NULL);
                 Tspi_Context_Close(hContext);
                 exit(result);
         }

	 // Set password
         result = Tspi_Policy_SetSecret(hPolObject, TSS_SECRET_MODE_PLAIN, auth_length, auth);
         if (result != TSS_SUCCESS)
         {
                 print_error("Tspi_Policy_SetSecret", result);
                 print_error_exit(nameOfFunction, err_string(result));
                 Tspi_Context_FreeMemory(hContext, NULL);
                 Tspi_Context_Close(hContext);
                 exit(result);
         }
 
         // Assign to Object
         result = Tspi_Policy_AssignToObject(hPolObject, hNVStore);
         if (result != TSS_SUCCESS)
         {
                 print_error("Tspi_Policy_AssignToObject", result);
                 print_error_exit(nameOfFunction, err_string(result));
                 Tspi_Context_FreeMemory(hContext, NULL);
                 Tspi_Context_Close(hContext);
                 exit(result);
         }

	// Set the Index to be Defined
	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0, 0x00011133);
        if (result != TSS_SUCCESS)
        {
                print_error("Tspi_SetAttribUint32 for setting NV index", result);
                print_error_exit(nameOfFunction, err_string(result));
                Tspi_Context_FreeMemory(hContext, NULL);
                Tspi_Context_Close(hContext);
                exit(result);
        }

	// Set the Permission for the Index
	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_PERMISSIONS, 0, 0x4);
       	if (result != TSS_SUCCESS)
        {
                print_error("Tspi_SetAttribUint32 for setting permission", result);
                print_error_exit(nameOfFunction, err_string(result));
                Tspi_Context_FreeMemory(hContext, NULL);
                Tspi_Context_Close(hContext);
                exit(result);   
        }

	// Set the datasize to be defined
	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_DATASIZE, 0, i);
        if (result != TSS_SUCCESS)
        {
                print_error("Tspi_SetAttribUint32 for setting data size", result);
                print_error_exit(nameOfFunction, err_string(result));
                Tspi_Context_FreeMemory(hContext, NULL);
                Tspi_Context_Close(hContext);
                exit(result);
        }
	
	/* Define NV Space */
	result = Tspi_NV_DefineSpace(hNVStore, 0, 0);

	// Create Context
        result = Tspi_Context_Create(&hContext);
        if (result != TSS_SUCCESS) {
                 print_error("Tspi_Context_Create ", result);
                 print_error_exit(nameOfFunction, err_string(result));
                 exit(result);
        }
        
	// Connect Context
	result = Tspi_Context_Connect(hContext,NULL);
        if (result != TSS_SUCCESS) {
                 print_error("Tspi_Context_Connect", result);
                 print_error_exit(nameOfFunction, err_string(result));
                 Tspi_Context_FreeMemory(hContext, NULL);
                 Tspi_Context_Close(hContext);
                 exit(result);
        }

	// Create TPM NV object
        result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0,&hNVStore);
        if (result != TSS_SUCCESS)
        {
                 print_error("Tspi_Context_CreateObject", result);
                 print_error_exit(nameOfFunction, err_string(result));
                 Tspi_Context_FreeMemory(hContext, NULL);
                 Tspi_Context_Close(hContext);
                 exit(result);
        }

 	// Create policy object for the NV object
        result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hPolObject);
        if (result != TSS_SUCCESS)
        {
                 print_error("Tspi_Context_CreateObject", result);
                 print_error_exit(nameOfFunction, err_string(result));
                 Tspi_Context_FreeMemory(hContext, NULL);
                 Tspi_Context_Close(hContext);
                 exit(result);
        }
 
        // Set password
        result = Tspi_Policy_SetSecret(hPolObject, TSS_SECRET_MODE_PLAIN, auth_length, auth);
        if (result != TSS_SUCCESS)
        {
                 print_error("Tspi_Policy_SetSecret", result);
                 print_error_exit(nameOfFunction, err_string(result));
                 Tspi_Context_FreeMemory(hContext, NULL);
                 Tspi_Context_Close(hContext);
                 exit(result);
        }
 
         // Set password 
         result = Tspi_Policy_AssignToObject(hPolObject, hNVStore);
         if (result != TSS_SUCCESS)
         {
                 print_error("Tspi_Policy_AssignToObject", result);
                 print_error_exit(nameOfFunction, err_string(result));
                 Tspi_Context_FreeMemory(hContext, NULL);
                 Tspi_Context_Close(hContext);
                 exit(result);
         }

         /* Set the index to be defined */
         result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0,0x00011133);
         if (result != TSS_SUCCESS)
         {
                 print_error("Tspi_SetAttribUint32 for setting NV index", result);
                 print_error_exit(nameOfFunction, err_string(result));
                 Tspi_Context_FreeMemory(hContext, NULL);
                 Tspi_Context_Close(hContext);
                 exit(result);
         }

         result = Tspi_NV_WriteValue(hNVStore, /*offset*/0, i, data);
/*	
	Tspi_Context_GetTpmObject(hContext, &hTPM);
	Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hPolicy);
	Tspi_Policy_SetSecret(hPolicy, TESTSUITE_OWNER_SECRET_MODE, TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);
	Tspi_NV_ReleaseSpace(hNVStore);
*/
	if (result== TSS_SUCCESS)
	{
		print_success(nameOfFunction, result);
		printf("\tGood at %i Bytes\n", i);
                Tspi_NV_ReleaseSpace(hNVStore);
		Tspi_Context_FreeMemory(hContext, NULL);
                Tspi_Context_Close(hContext);
		return result;
	
	}	
	
	else{
                print_error("Tspi_NV_DefineSpace", result);
                printf("\tFailed at %i Bytes\n", i);
                print_end_test(nameOfFunction);
                Tspi_Context_FreeMemory(hContext, NULL);
                Tspi_Context_Close(hContext);
		return result;
                //exit(result);
        }
	
	free(data);
	data=NULL;
}

int nv_stress(BYTE data2write[], int size)
{
	char	     *nameOfFunction    = "NV_Stress_Test";
	char	     *nameOfWrite       = "NV_Write_Test";
	char	     *nameOfRead        = "NV_Read_Test";
	
	TSS_HCONTEXT hContext           = NULL_HCONTEXT;
	TSS_HNVSTORE hNVStore           = 0;//NULL_HNVSTORE
	TSS_HOBJECT  hPolObject         = NULL_HOBJECT;
	TSS_HPOLICY  hPolicy            = NULL_HPOLICY;
	TSS_HTPM     hTPM               = NULL_HTPM;
      	BYTE         *auth              = "123456";
	UINT32       auth_length        = 6;
	BYTE	     *data2read;
	TSS_RESULT   result;
	
	print_begin_test(nameOfFunction);

		/* Create Context */
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
		/* Connect Context */
	result = Tspi_Context_Connect(hContext,NULL);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect_1", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL); 
		Tspi_Context_Close(hContext);
		exit(result);
	}

	    	/* Create TPM NV object */
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0,&hNVStore);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		/* Get TPM object */
	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Context_GetTpmObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hPolicy);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		/* Set password */
	result = Tspi_Policy_SetSecret(hPolicy, TESTSUITE_OWNER_SECRET_MODE,
					TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);

	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Create policy object for the NV object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hPolObject);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Set password
	result = Tspi_Policy_SetSecret(hPolObject, TSS_SECRET_MODE_PLAIN, auth_length, auth);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Set password
	result = Tspi_Policy_AssignToObject(hPolObject, hNVStore);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Policy_AssignToObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Set the index to be defined
	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0, 0x00011133);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_SetAttribUint32 for setting NV index", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Set the permission for the index
	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_PERMISSIONS, 0, 0x4);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_SetAttribUint32 for setting permission", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);	
       }

		// Set the data size to be defined
	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_DATASIZE, 0, size);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_SetAttribUint32 for setting data size", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
     	}

		/*Define NV space*/
	result = Tspi_NV_DefineSpace(hNVStore, 0, 0);

		/* Create Context */
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}

		/* Connect Context */
	result = Tspi_Context_Connect(hContext,NULL);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);   
		Tspi_Context_Close(hContext);
		exit(result);
	}

	    	/* Create TPM NV object */
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0,&hNVStore);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Create policy object for the NV object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hPolObject);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Set password
	result = Tspi_Policy_SetSecret(hPolObject, TSS_SECRET_MODE_PLAIN, auth_length, auth);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Set password
	result = Tspi_Policy_AssignToObject(hPolObject, hNVStore);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Policy_AssignToObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	
		// Set the index to be defined
	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0, 0x00011133);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_SetAttribUint32 for setting NV index", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	unsigned int ctr;

	FILE *logFile;
	
	logFile = fopen("/root/kuanjuwu/testsuite-0.3/tcg/nv/ctr.txt", "r");
	
	if(logFile == NULL){

		ctr=0;
		printf("Stress Test Counter start from %d\n", ctr);
	}	
		
	
	else{
		fscanf(logFile, "%d", &ctr);	
		printf("Stress Test Counter start from %d\n", ctr);
		fclose(logFile);
	}
		

	//int ctr=0;

	while(1){
		
		FILE *cFile;
		cFile = fopen("/root/kuanjuwu/testsuite-0.3/tcg/nv/ctr.txt", "w");
		
		if(cFile == NULL)
		exit(-1);
		
		else{
		fprintf(cFile, "%d\n", ctr);
		fclose(cFile);
		}
		
		ctr++;

		int i;
		FILE *pFile;
		pFile = fopen("/dev/urandom", "r");
		
		if(pFile == NULL)
			exit(-1);

		else{
			for(i=0; i<size; i++)	
			data2write[i] = fgetc(pFile);
			fclose(pFile);
		}

		/* NV_Write */
	result = Tspi_NV_WriteValue(hNVStore, /*offset*/0,/*datalength*/size, data2write);  

/*		Tspi_Context_GetTpmObject(hContext, &hTPM);
		Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hPolicy);
		Tspi_Policy_SetSecret(hPolicy, TESTSUITE_OWNER_SECRET_MODE,
					TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);
		Tspi_NV_ReleaseSpace(hNVStore);
*/      
       if (result== TSS_SUCCESS)
       {              
        	print_success(nameOfWrite, result);
		//print_end_test(nameOfFunction);
		printf("\tNV_Write at %i bytes!\n", size);
		Tspi_Context_FreeMemory(hContext, NULL);
		//Tspi_Context_Close(hContext);
		//exit(0);
       }
       else{
		print_error(nameOfWrite, result);
		printf("NV_Write Failed at %i bytes!\n", size);
		print_end_test(nameOfWrite);
		printf("Count: %d\n", ctr);
		//Tspi_NV_ReleaseSpace(hNVStore);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
     	}

		/* NV_Read */
	result = Tspi_NV_ReadValue(hNVStore,/*read_offset*/0, /*&read_space*/&size, &data2read);	

/*		Tspi_Context_GetTpmObject(hContext, &hTPM);
		Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hPolicy);
		Tspi_Policy_SetSecret(hPolicy, TESTSUITE_OWNER_SECRET_MODE,
					TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);
		Tspi_NV_ReleaseSpace(hNVStore);
*/
       	if (result == TSS_SUCCESS)
       	{
		print_success(nameOfRead, result);
		
		printf("\tNV_Read at %d bytes\n", size);

		//printf("%s\n", data2read);
		printf("\tCount: %d\n", ctr);
		//Tspi_NV_ReleaseSpace(hNVStore);
                //Tspi_Context_FreeMemory(hContext, NULL);
                //Tspi_Context_Close(hContext);
                //exit(0);
	}
       
	else{
                print_error("Tspi_NV_ReadValue1", result);
                print_end_test(nameOfRead);
		printf("NV_Read Failed at %i bytes\n", size);
		Tspi_NV_ReleaseSpace(hNVStore);
                Tspi_Context_FreeMemory(hContext, NULL);
                Tspi_Context_Close(hContext);
                exit(result);
        	}

	if(ctr%10000==0){
		
		int i=memcmp(data2write, data2read, size);
	
		if(i!=0){
		
		printf("R/W DATA are NOT matched!\n");
		exit(1);
		
		}
		
		printf("\tR/W DATA are Matched!\n");
	}
	
	}
	
}
