#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include "libalt2.h"

//Parametro de entorno, la altitud
unsigned char* params[1];

typedef unsigned char *PUCHAR;

PUCHAR* getChallengeProtectParams(){//Me da la altitud, que se obtiene del entorno

	int i;
	char var[10];
	
	FILE* file = fopen ("/home/pi/Desktop/hola.txt", "r");
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
 	int alt0 = 0;
	int cuanto = 2;
	//Resto alt menos alt0, para tener el cuanto bien en funcionde alt0
	alt = alt-alt0;//Deberia ser resta del valor absoluto
	alt = alt/cuanto;
	sprintf(params[0],"%d",alt); 
	//printf("%s\n", params[0]);
	return params;
}

PUCHAR* getChallengeUnProtectParams(){//Me da la altitud, o lo que sea

	int i;
	char var[10];
	
	FILE* file = fopen ("/home/pi/Desktop/hola.txt", "r");
	fscanf (file, "%d", &i);
	fclose(file);

	//printf("%d\n",i);
	sprintf(var,"%d",i);
	params[0] = malloc(strlen(var)+1);
	strcpy(params[0],var);
	return params;
}

PUCHAR execute(PUCHAR* parametrosXml){
	//int alt = atoi(params[0]);
	int alt = atoi(parametrosXml[0]);
	int alt0 = 0;
	int cuanto = 2;
	//Resto alt menos alt0, para tener el cuanto bien en funcionde alt0
	alt = alt-alt0;
	alt = alt/cuanto;
	//alt = alt/2;
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
	printf("Desproteger: %s\n",execute(params));
	//printf("Proteger: %s\n",executeParam());
}*/

