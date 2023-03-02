
/**Fichero: Principal.java
 * Clase para comprobar el funcionamiento de las otras clases del paquete.
 * Asignatura: SEG
 * @author Profesores de la asignatura
 * @version 1.0
 */

import java.util.Scanner;


public class Principal {

	public static void main (String [ ] args) {
		int menu1;
		int menu2;
		Scanner sc = new Scanner(System.in);
		/* completar declaracion de variables e instanciaci�n de objetos */
		
		
		Simetrico simetrico = new Simetrico();
		
		
		do {
			System.out.println("�Qu� tipo de criptograf�a desea utilizar?");
			System.out.println("1. Sim�trico.");
			System.out.println("2. Asim�trico.");
			System.out.println("3. Salir.");
			menu1 = sc.nextInt();
		
			switch(menu1){
				case 1:
					do{
						System.out.println("Elija una opci�n para CRIPTOGRAFIA SIM�TRICA:");
						System.out.println("0. Volver al men� anterior.");
						System.out.println("1. Generar clave.");
						System.out.println("2. Cifrado.");
						System.out.println("3. Descifrado.");
						menu2 = sc.nextInt();
				
						switch(menu2){
							case 1:
								/*completar acciones*/
								System.out.println("Elija un nombre para el fichero de la clave");
								String nombreFichero = sc.next();
								simetrico.generarClave(nombreFichero);
							break;
							case 2:
								/*completar acciones*/
								System.out.println("Escriba el nombre del fichero donde esta la clave");
								String ficheroClave = sc.next();
								System.out.println("Escriba el nombre del fichero a cifrar");
								String ficheroClaro = sc.next();
								System.out.println("Escriba el nombre del fichero para guardar cifrado");
								String ficheroCifrado = sc.next();
								simetrico.Cifrar(ficheroClave, ficheroClaro, ficheroCifrado);
							break;
							case 3:
								/*completar acciones*/
								System.out.println("Escriba el nombre del fichero donde esta la clave");
								ficheroClave = sc.next();
								System.out.println("Escriba el nombre del fichero a cifrado");
								ficheroCifrado = sc.next();
								System.out.println("Escriba el nombre del fichero para guardar cifrado");
								String ficheroDescifrado = sc.next();
								simetrico.Cifrar(ficheroClave, ficheroCifrado, ficheroDescifrado);
							break;
						}
					} while(menu2 != 0);
				break;
				case 2:
					do{
						System.out.println("Elija una opci�n para CRIPTOGRAFIA ASIM�TRICA:");
						System.out.println("0. Volver al men� anterior.");
						System.out.println("1. Generar clave.");
						System.out.println("2. Cifrado.");
						System.out.println("3. Descifrado.");
						System.out.println("4. Firmar digitalmente.");
						System.out.println("5. Verificar firma digital.");
						menu2 = sc.nextInt();
				
						switch(menu2){
							case 1:
								/*completar acciones*/
							break;
							case 2:
								/*completar acciones*/
							break;
							case 3:
								/*completar acciones*/
							break;
							case 4:
								/*completar acciones*/
							break;
							case 5:
								/*completar acciones*/
							break;
						}
					} while(menu2 != 0);
				break;
			}			
		} while(menu1 != 3);
		sc.close();
	}
}