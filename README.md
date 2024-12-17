Introducción 
Por medio de este documento se presenta y brinda información sobre la aplicación creada para la captura y análisis de paquetes por medio de NPCAP (librería que se encarga del procesamiento de este tipo de datos), este mismo programa será brindado en la misma carpeta del presente documento, esto a fin de brindar al usuario herramientas para obtener información del tráfico de red, de la cual su dispositivo sea parte. Con este objetivo solicitamos al usuario lea la información presente en las siguientes páginas para el correcto funcionamiento de la aplicación.
Requisitos Previos
Es necesario que el usuario tenga pleno conocimiento de sus adaptadores de red que estén actualmente en funcionamiento, la aplicación brinda una lista de los identificados por el programa, sin embargo, es necesario el usuario seleccione alguno que actualmente este activo y recibiendo paquetes, para poder analizar los mismos.

Instalación
La instalación consta con una carpeta con dos aplicaciones y un paquete de Windows
 
La aplicación npcap es un instalador de este mismo y es necesario para que la aplicación pueda ser usada adecuadamente, es decir, sin esta la aplicación no funciona.
Es importante que al realizar la instalación del npcap instalarlo en WinPcap
 
Una vez ya instalado el npcap ya podemos pasar a la instalación de la aplicación, podemos usar cualquiera de los dos instaladores restantes que aparecen en la carpeta, lo importante es que los dos deben de estar en esta misma.
 
Al seleccionar siguiente nos pedirá la ruta de descarga, es importante poner esta ruta en la misma carpeta en la que se encuentran los tres instaladores. Como en mi caso yo tengo la carpeta en la ruta que se muestra en la imagen a continuación la instalación la hago en la misma ruta/carpeta.
 
 
Una vez seleccionada la carpeta se procederá la instalación, cuando finalice tendremos todo lo necesario para ejecutar la aplicación que automáticamente tendrá una ruta para abrirla en el escritorio.
 
Al dar doble click se ejecutará la aplicación y si toda la instalación se hizo correctamente no presentara ningún problema en su ejecución.


Funciones básicas
Menú de Usuario.
Es el apartado principal con el cual se hará interacción del usuario, representado por una barra de menú ubicada en el borde superior, por medio de esta barra se darán indicaciones para que el programa realice las tareas que necesite el usuario, así como definir parámetros, o guardar datos en un archivo CSV.
 
 
Este se define por 3 apartados los cuales cuentan con un objetivo diferente entre si, cada uno de ellos permite crear e implementar los datos o herramientas que el usuario necesite.

Archivo – Guardar Captura:
En este apartado al abrirlo se desplazará un botón secundario para el almacenamiento de los datos de captura que se hayan generado anteriormente, por medio del cual se mostrará una interfaz que permita manipular el nombre ya que esto lo que hace es sobrescribir los datos de la captura actual con otra pasada.
 

Parámetros – Adaptador de red:
En esta sección se busca que el usuario seleccione la interfaz de red con la cual quiera realiza la captura de paquetes, en caso de seleccionar una red el mismo programa te lo indicara.
 
 

Captura – Inicio/Detener:
En esta sección se cuenta con dos botones los cuales como su mismo nombre indica son para comenzar la captura y detenerla, es importante aclarar que, al empezar una captura sin haber seleccionado un dispositivo de red, se enviara un mensaje recordatorio de que se tiene que seleccionar, ya que sin el dispositivo escogido no se puede realizar la captura, de igual manera el botón de detener no funciona hasta que se inicie una captura.
 

Apartado de Filtros
Esta sección se encuentra en la parte de debajo del menú de usuario en donde se le puede escribir una filtración dada por el usuario para la captura de paquetes, es importante aclarar que al escribir el filtro deseado es necesario darle a filtrar y enseguida iniciar de nuevo la captura de paquetes ya que esta se detiene al ingresar un filtro/filtro nuevo.
 
Los filtros que son validos de ingresar con su respectiva nomenclatura de encuentran a continuación:
src<espacio><seguido de la dirección>
 
dst<espacio><seguido de la dirección>
 
udp
 
Idp
 
Ip
 
Si lo que se busca es ahora limpiar los filtros de captura, solo basta con borrar el texto puesto en la barra y volver filtrar la barra para limpiar correctamente y no olvidar el volver a dar al botón de inicio para reanudar la captura de paquetes
Sub-ventana de Paquetes Capturados
 
Como se muestra en la imagen esta sección cuenta con los paquetes que se están capturando del dispositivo de red en tiempo real, esta sección desglosa los paquetes en nueve secciones ID, SRC, DST, TTL, No.Protocolo, Protocolo, SPORT, DPORT y Flags del paquete, cabe aclarar que se puede seleccionar cada paquete para verlo desglosado en las pantallas de abajo sin antes haber cliquear alguna de estas dos pantallas encontradas en la parte de abajo.
Sub-ventanas Información de paquetes.
En estas ventanas podemos encontrar la información que contiene el paquete seleccionado por el usuario, es importante aclarar el hecho de que es necesario que cada vez que es seleccionado el paquete escogido para ser desglosado, cliquear alguna de estas dos ventanas ya que sin esto no será actualizado el contenido del paquete, es decir “selección-paquete” -> clic en una ventana de abajo -> “selección-paquete” ->clic en una ventana de abajo.
 
Las dos ventanas se dividen de la siguiente manera.
Información Hexadecimal:
Aqui se obtuvieron los datos extraibles del paquete, los cuales estan en hexadecimal.
 
Información Decodificada:
Es la traducción de los paquetes del hexadecimal.
 
