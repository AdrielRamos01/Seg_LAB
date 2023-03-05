
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
		/* completar declaracion de variables e instanciación de objetos */
		
		
		Simetrico simetrico = new Simetrico();
		Asimetrico asimetrico = new Asimetrico();
		String tipoClave;
		
		
		do {
			System.out.println("¿Qué tipo de criptografía desea utilizar?");
			System.out.println("1. Simétrico.");
			System.out.println("2. Asimétrico.");
			System.out.println("3. Salir.");
			menu1 = sc.nextInt();
		
			switch(menu1){
				case 1:
					do{
						System.out.println("Elija una opción para CRIPTOGRAFIA SIMÉTRICA:");
						System.out.println("0. Volver al menú anterior.");
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
								simetrico.Descifrar(ficheroClave, ficheroCifrado, ficheroDescifrado);
							break;
						}
					} while(menu2 != 0);
				break;
				case 2:
					do{
						System.out.println("Elija una opción para CRIPTOGRAFIA ASIMÉTRICA:");
						System.out.println("0. Volver al menú anterior.");
						System.out.println("1. Generar clave.");
						System.out.println("2. Cifrado.");
						System.out.println("3. Descifrado.");
						System.out.println("4. Firmar digitalmente.");
						System.out.println("5. Verificar firma digital.");
						menu2 = sc.nextInt();
				
						switch(menu2){
							case 1:
								/*completar acciones*/
								System.out.println("Escriba el nombre del fichero donde esta la clave Publica");
								String ficheroClavePublica = sc.next();
								System.out.println("Escriba el nombre del fichero donde esta la clave Privada");
								String ficheroClavePrivada = sc.next();
								asimetrico.generarClaves(ficheroClavePublica, ficheroClavePrivada);
								
							break;
							case 2:
								/*completar acciones*/
								do {
                                    System.out.println("Indique con qué clave desea cifrar: privada o publica");
                                    tipoClave = sc.next();
                                    if (tipoClave.equals("privada") || tipoClave.equals("publica")) {
                                        System.out.println("Introduzca el nombre del fichero que tiene la clave: ");
                                        String fClave = sc.next();
                                        System.out.println("Introduzca el nombre del fichero que se quiere cifrar: ");
                                        String fEntrada = sc.next();
                                        System.out.println("Introduzca el nombre del fichero de salida (cifrado): ");
                                        String fSalida = sc.next();
                                        asimetrico.cifrar(tipoClave, fClave, fEntrada, fSalida);
                                    } else {
                                        System.out.println("No se ha introducido un valor correcto");
                                    }
                                }while(!tipoClave.equals("privada") && !tipoClave.equals("publica"));
							break;
							case 3:
								/*completar acciones*/
								do {
                                    System.out.println("Indique con qué clave desea descifrar: privada o publica");
                                    tipoClave = sc.next();
                                    if (tipoClave.equals("privada") || tipoClave.equals("publica")) {
                                        System.out.println("Introduzca el nombre del fichero que tiene la clave: ");
                                        String fClave = sc.next();
                                        System.out.println("Introduzca el nombre del fichero que se quiere descifrar: ");
                                        String fEntrada = sc.next();
                                        System.out.println("Introduzca el nombre del fichero de salida (descifrado): ");
                                        String fSalida = sc.next();
                                        asimetrico.descifrar(tipoClave, fClave, fEntrada, fSalida);
                                    } else {
                                        System.out.println("No se ha introducido un valor correcto");
                                    }
                                }while(!tipoClave.equals("privada") && !tipoClave.equals("publica"));
							break;
							case 4:
								/*completar acciones*/
								System.out.println("Introduzca el nombre del fichero que tiene la clave privada: ");
                                String fClave = sc.next();
                                System.out.println("Introduzca el nombre del fichero que quiere firmar: ");
                                String fFirmar = sc.next();
                                System.out.println("Introduzca el nombre del fichero donde se guarda la firma: ");
                                String fFirmado = sc.next();
                                asimetrico.firmar(fClave, fFirmar, fFirmado);
							break;
							case 5:
								/*completar acciones*/
								System.out.println("Introduzca el nombre del fichero que tiene la clave publica: ");
                                String fClavePub = sc.next();
                                System.out.println("Introduzca el nombre del fichero claro: ");
                                String fClaro = sc.next();
                                System.out.println("Introduzca el nombre del fichero donde está el resumen cifrado: ");
                                String fResumenCifrado = sc.next();
                                boolean verificado = asimetrico.verificarFirma(fClavePub, fClaro, fResumenCifrado);
                                
                                if (verificado) {
                                	System.out.println("Fichero verificado con exito ");
                                } else {
                                	System.out.println("Fichero no verificado ");
                                }
							break;
						}
					} while(menu2 != 0);
				break;
			}			
		} while(menu1 != 3);
		sc.close();
	}
}