//includes
#include<stdio.h>
#include<math.h>

//Variables globales
double params[4];//0:latmax,1:latmin,2:longmax,3;longmin
double params0[4];
int numtesela;

//funciones
//recorrer fichero para coger las 4 esquinas
void esquinas(){
	//primero recorro el fichero
	FILE *rutas;
	double pos;
	char sep;
	double latmax = -90; //Latitud minima
	double longmax = -180;//Longitud minima
	double latmin = 90; //Latitud max
	double longmin = 180;//Longitud max
	int nlineas = 0;
	int tam;
	rutas = fopen("ruta","r")	;
	while(!feof(rutas)){
		tam = fscanf(rutas,"%lf",&pos);//Leo lat
		if (tam==-1){break;}//Si la linea esta vacia, me salgo
		//printf("leo: %d ;",fscanf(rutas,"%lf",&pos));
		if (pos>=latmax){latmax=pos;}
		if (pos<=latmin){latmin=pos;}
		fscanf(rutas,"%c",&sep);	//Leo ;
		//printf("lat: %.10f ;",pos);
		tam = fscanf(rutas,"%lf",&pos);//Leo lng
		if (tam==-1){break;}//Si la linea esta vacia, me salgo
		//printf("leo: %d ;",fscanf(rutas,"%lf",&pos));
		if(pos>=longmax){longmax=pos;}
		if (pos<=longmin){longmin=pos;}
		//printf("lng: %.10f\n",pos);
		nlineas++;
	}
	fclose(rutas);
	//printf("Lineas: %d\n",nlineas);
	printf("lat = %.10lf lng = %.10f\n",latmax,longmax);
	printf("lat = %.10f lng = %.10f\n",latmin,longmin);
	//HAY QUE COMPONER LAS ESQUINAS
  //Esquina sup-izq: latmin longmax
	//printf("Esquina SupIzq: %.10f , %.10f\n",latmin,longmax);
	//supdcha: latmax longmax
	//printf("Esquina SupDer: %.10f , %.10f\n",latmax,longmax);
	//infizq: latmin longmin
	//printf("Esquina InfIzq: %.10f , %.10f\n",latmin,longmin);
	//infder: latmax longmin
	//printf("Esquina InfDer: %.10f , %.10f\n",latmax,longmin);
	//Alto y ancho
	//printf("Alto = %.10f Ancho = %.10f\n",latmax-latmin,longmax-longmin);//Ojo esto cambia si son positivos o negativos
	params[0]=latmax;
	params[1]=latmin;
	params[2]=longmax;
	params[3]=longmin;
}

void tesela0(){
	//Obtengo alto y ancho
	double alto = params[0]-params[1];
	double ancho = params[2]-params[3];
	printf("El alto es %.10f\n",alto);
	printf("El ancho es %.10f\n",ancho);
	//calculo offset respecto a 0 y lo meto en params0
	double offsety = params[0]/alto;
	double offsetx = params[2]/ancho;
	printf("Offsety: %.10f, y Offsetx: %.10f\n",offsety,offsetx);
	//Me quedo con la parte decimal y tengo los puntos donde empieza	
	int offsetyi = (int)offsety;
	int offsetxi = (int)offsetx;
	printf("Offsetyi: %d, y Offsetxi: %d\n",offsetyi,offsetxi);
	offsety = offsety-offsetyi;
	offsetx = offsetx-offsetxi;
	//Les sumo alto y ancho y obtengo los params0
	params0[0]= offsety + alto;
	params0[1]= offsety;
	params0[2]=	offsetx + ancho;
	params0[3]=	offsetx;
	printf("Parametros tesela 0: %.10f, %.10f, %.10f, %.10f\n",params0[0],params0[1],params0[2],params0[3]);
	numtesela = offsetxi+offsetyi;//Por ejemplo
	printf("La tesela en la que corre el coche es: %d\n",numtesela);
}

void checkPunto(){//Esto es lo que se hará en la desproteccion, solo tienes punto actual y tesela 0.
	//
}

int main(){
	esquinas();
	//printf("%.10f\n",params[0]);
	tesela0();
	return 0;
}
