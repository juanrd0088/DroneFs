#include <string.h>
#include <malloc.h>
#include <stdlib.h>

//Supongo que es para la altitud
unsigned char* params[1];

typedef unsigned char *PUCHAR;

PUCHAR* getChallengeProtectParams(){//Me da la altitud, o lo que sea

	int i;
	char var[10];
	
	FILE* file = fopen ("/home/jrd/Escritorio/adios.txt", "r");
	fscanf (file, "%d", &i);
	fclose(file);

	//printf("%d\n",i);
	sprintf(var,"%d",i);
	params[0] = malloc(strlen(var)+1);
	strcpy(params[0],var);
	//printf("%s\n", var);
	return params;
}

PUCHAR* executeParam(){
	int alt = atoi(params[0]);
	alt = alt/2;
	sprintf(params[0],"%d",alt); 
	return params;
}

PUCHAR* getChallengeUnProtectParams(){//Me da la altitud, o lo que sea

	int i;
	char var[10];
	
	FILE* file = fopen ("/home/jrd/Escritorio/adios.txt", "r");
	fscanf (file, "%d", &i);
	fclose(file);

	//printf("%d\n",i);
	sprintf(var,"%d",i);
	params[0] = malloc(strlen(var)+1);
	strcpy(params[0],var);
	//printf("%s\n", var);
	return params;
}

PUCHAR execute(PUCHAR* parametrosXml){
	//int alt = atoi(params[0]);
	int velocidad = atoi(parametrosXml[0]);//No la toco porque por ahora el cuanto se corresponde con la real
	sprintf(parametrosXml[0],"%d",alt); 
	return parametrosXml[0];
}

PUCHAR* getParamNames(){
	return NULL;
}

int getNParams(){
	return 0;
}

/*int main(){
	getChallengeProtectParams();
	//printf("%s\n",params[0]);
	//executeParam();
	printf("%s\n",execute(params));
}*/

