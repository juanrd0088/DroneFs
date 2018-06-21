En este apartado se explica como poner en marcha el minifilter de Windows, que viene ya con el módulo de cifrado y challenges integrados. Además, se explican las condiciones que deben cumplir los challenges para que se pasen o no.
#Minifilter de Windows
Descarga
Se descarga desde el git habilitado: 
https://git.code.tecnalia.com/ander.juaristi/device-monitor/tree/NOKIA-CiberDrone/DroneFSfilter

Instalación
===========

En Windows, DroneFS dispone de dos componentes: el minifilter como tal, que es un driver, y la aplicación de usuario que se comunica con este driver. 
El minifilter, al ser un driver, basta con hacer click derecho en el archivo INF que se ha descargado previamente para instalarlo.El archivo inf está dentro de la carpeta x64/Debug o Release: C:\W10 PC\Projects\DroneFSfilter\x64\Debug. La aplicación de usuario se puede ejecutar directamente desde el archivo dronefsuser.exe.

Puesta en marcha
================

Para iniciar el minifilter, abrimos una consola y ejecutamos:
 	sc start DroneFSFilter (inicia el driver)

Ejecutar el dronefsuser.exe (desde el visual en administrador para debuggear o desde el exe en modo admin)
Tenemos creado un fichero “demotest.txt” con texto en claro

En otro consola, ejecutamos 
subl “T:\demo\demotest.txt” 
con lo que abrimos el archivo de texto. 

Como es la primera vez que se abre dicho archivo con el minifilter activo y no posee cabecera, no se están ejecutando los challenges. 
Escribimos algo de texto y guardamos. Ahora el minifilter ejecutará los challenges y guardará el archivo cifrado con una cabecera de DroneFS.

Si queremos ver el contenido real del fichero, cerramos el minifilter para simular que estamos en otro ordenador que no tenga el driver. Para ello, cerramos primero DroneFSUser y luego hacemos en consola:
	sc stop DroneFSFilter
	
Volvemos a abrir el fichero .txt (lo habremos cerrado previamente el sublime) y comprobamos que está cifrado y con el header.
Si queremos ver que funciona el driver descifrando, iniciamos de nuevo el minifilter y la aplicación dronefsuser y abrimos el archivo.
NOTA: los challenges que se ejecutan se especifican en el archivo dronefsconfig.txt que se encuentra en la misma ruta que dronefsuser.exe. Ahí se encuentran también las DLL de los challenges. Ojo con el parámetro “count” que tiene que ser igual al número de challenges.
