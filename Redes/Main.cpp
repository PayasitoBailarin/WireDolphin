//importante!!!!!!!
//nomenclatura de los comentarios:
// * refiere a borrar cuando sea necesario
// - inicio o final de algun bloque relevante
#define _CRT_SECURE_NO_WARNINGS
#define ID_LISTBOX 102 // Identificador para el ListBox
#define IDM_ADAPTADOR_DE_RED 101
#define IDM_BTN_INICIAR 201
#define IDM_BTN_DETENER 202
#define IDM_BTN_GUARDAR 203
#define WM_UPDATE_PAYLOAD (WM_USER+2)

#include <iostream>

#include <string.h>
#include <pcap.h>
#include <stdlib.h>
#include <winsock2.h>
#include <stdint.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <Control.h>
#include <Windows.h>
#include <thread>
#include <iphlpapi.h>
#include <vector>
#include <string>
#include <codecvt>
#include <locale>
#include <iomanip>
#include <sstream>
#include <commdlg.h>
#include <cstdlib>
using namespace std;

vector<string> hexadecimal;

int dispositivoSeleccionadoAux = -1;
bool escojioAdaptador = false;
bool seleccionoIniciar = false;
int auxDetener = 0;
char dispositivoSeleccionadoNombre[10][80];//para guardar el nombre de la red
char dispositivoSeleccionado[10][80]; // Ajustar tamaño para incluir el nombre completo
char filtro[50] = "";
const char* filters = filtro;

HWND hWnd;
HWND hPacket;
HWND hVistaPaquete;
HWND hProtocolos;
HWND hFiltro;
HWND hBoton;
HMENU menuAplicacion();
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK NuevaVentanaProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

#define WM_UPDATE_LISTBOX (WM_USER + 1)



#pragma comment(lib, "ws2_32.lib") // Vincular la biblioteca de sockets de Windows
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
// Estructura TCP (simplificada)
struct tcphdr {
    uint16_t source;     // Puerto de origen
    uint16_t dest;       // Puerto de destino
    uint32_t seq;        // Número de secuencia
    uint32_t ack_seq;    // Número de acuse de recibo
    uint8_t th_res1 : 4; // Bits reservados
    uint8_t th_off : 4;  // Longitud del encabezado
    uint8_t th_flags;    // Flags TCP
    uint16_t window;     // Tamaño de ventana
    uint16_t check;      // Checksum
    uint16_t urg_ptr;    // Puntero urgente
    u_char doff;        //apartado para definir el payload 
};

// Estructura UDP (simplificada)
struct udphdr {
    uint16_t source;    // Puerto de origen
    uint16_t dest;      // Puerto de destino
    uint16_t len;       // Longitud
    uint16_t check;     // Checksum
};


// Definir manualmente la estructura IP en Windows
struct iphdr {
    unsigned char ihl : 4;  // Longitud del encabezado
    unsigned char version : 4;  // Versión
    uint8_t tos;  // Tipo de servicio
    uint16_t tot_len;  // Longitud total
    uint16_t id;  // ID del paquete
    uint16_t frag_off;  // Offset de fragmento
    uint8_t ttl;  // Tiempo de vida
    uint8_t protocol;  // Protocolo
    uint16_t check;  // Checksum
    struct in_addr saddr;  // Dirección IP de origen
    struct in_addr daddr;  // Dirección IP de destino
};

// Definir encabezado ICMP manualmente
struct icmp_hdr {
    uint8_t type;    // Tipo de mensaje ICMP
    uint8_t code;    // Código del mensaje
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
};

// Longitud del encabezado de enlace
int link_hdr_length = 0;

wstring stringToWString(const string& str) {
    // Convierte std::string a std::wstring (para UTF-8)
    wstring_convert<codecvt_utf8<wchar_t>> converter;
    return converter.from_bytes(str);
}

void RenombrarArchivo(HWND hWnd) {
    OPENFILENAME ofn;
    wchar_t szNuevoNombre[260] = L""; // Buffer para el nuevo nombre del archivo
    wchar_t rutaActual[260] = L"captura.csv"; // Nombre fijo del archivo CSV en la carpeta actual

    // Configurar el cuadro de diálogo para el nuevo nombre
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFile = szNuevoNombre;  // Buffer para el nuevo nombre
    ofn.nMaxFile = sizeof(szNuevoNombre) / sizeof(wchar_t);
    ofn.lpstrFilter = L"Archivos CSV\0*.csv\0Todos los archivos\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = L"csv";

    if (GetSaveFileName(&ofn) == TRUE) {
        // Renombrar el archivo
        if (MoveFile(rutaActual, szNuevoNombre)) {
            MessageBox(hWnd, L"Archivo renombrado correctamente.", L"Éxito", MB_OK | MB_ICONINFORMATION);
        }
        else {
            MessageBox(hWnd, L"Error al renombrar el archivo. Verifica si existe captura.csv", L"Error", MB_OK | MB_ICONERROR);
        }
    }
}

void call_me(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packetd_ptr) {
    const u_char* payload_ptr = nullptr; // Puntero al inicio del payload
    int payload_length = 0;
    string result;
    char hexBuffer[4];

    if (auxDetener == 2) {
        return;
    }

    int packet_id;
    int packet_ttl;
    int packet_tos;
    int packet_protocol;
    int src_port;
    int dst_port;

    char cadena[14] = "";
    packetd_ptr += link_hdr_length;
    FILE* cvsfile = (FILE*)user;
    struct iphdr* ip_hdr = (struct iphdr*)(packetd_ptr); // Usar iphdr definido arriba
    packetd_ptr += ip_hdr->ihl * 4; // Saltar la longitud del encabezado IP

    char packet_srcip[INET_ADDRSTRLEN]; // Buffer para la IP de origen
    char packet_dstip[INET_ADDRSTRLEN]; // Buffer para la IP de destino

    // Usa inet_ntop para convertir las direcciones a formato legible
    inet_ntop(AF_INET, &(ip_hdr->saddr), packet_srcip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->daddr), packet_dstip, INET_ADDRSTRLEN);

    packet_id = ntohs(ip_hdr->id);
    packet_ttl = ip_hdr->ttl;
    packet_tos = ip_hdr->tos;
    packet_protocol = ip_hdr->protocol;

    struct tcphdr* tcp_header = (struct tcphdr*)packetd_ptr;
    char syn_flag = (tcp_header->th_flags & TH_SYN) ? 'S' : '-';
    char ack_flag = (tcp_header->th_flags & TH_ACK) ? 'A' : '-';
    char urg_flag = (tcp_header->th_flags & TH_URG) ? 'U' : '-';
    char fin_flag = (tcp_header->th_flags & TH_FIN) ? 'F' : '-';
    char rst_flag = (tcp_header->th_flags & TH_RST) ? 'R' : '-';
    char psh_flag = (tcp_header->th_flags & TH_PUSH) ? 'P' : '-';

    struct udphdr* udp_header = (struct udphdr*)packetd_ptr;
    src_port = ntohs(udp_header->source);
    dst_port = ntohs(udp_header->dest);

    const char* tipoPaquete = "";
    //cout << endl << packet_protocol << endl;
    if (packet_protocol == 6) {
        int tcp_header_length = tcp_header->doff * 4;
        payload_ptr = packetd_ptr + sizeof(struct tcphdr);
        payload_length = pkthdr->len - (payload_ptr - (const u_char*)packetd_ptr) - link_hdr_length;
        tipoPaquete = "TCP";
    }
    else if (packet_protocol == 17) {
        tipoPaquete = "UDP";
        struct udphdr* udp_header = (struct udphdr*)packetd_ptr;

        // Los puertos de origen y destino de UDP
        src_port = ntohs(udp_header->source);
        dst_port = ntohs(udp_header->dest);

        // Longitud del encabezado UDP
        int udp_header_length = sizeof(struct udphdr);

        // Avanzar al payload de UDP
        payload_ptr = packetd_ptr + udp_header_length;

        // Calcular la longitud del payload UDP correctamente
        payload_length = pkthdr->len - (payload_ptr - (const u_char*)packetd_ptr) - link_hdr_length - ip_hdr->ihl * 4 - udp_header_length;

        // Verificar que el cálculo sea correcto
        if (payload_length < 0) {
            // Si la longitud es negativa, significa que se está leyendo más allá del paquete real
            payload_length = 0;
        }
    }
    else if (packet_protocol == 128) {
        tipoPaquete = "IP";
    }
    else if (packet_protocol == 117) {
        tipoPaquete = "IATP";
    }
    else if (packet_protocol == 3) {
        tipoPaquete = "GGP";
    }
    else if (packet_protocol == 1) {
        tipoPaquete = "ICMP";
    }
    else if (packet_protocol == 2) {
        tipoPaquete = "IGMP";
    }
    else if (packet_protocol == 0) {
        tipoPaquete = "HOPOTP";
    }
    else if (packet_protocol >= 145 || packet_protocol <= 252) {
        tipoPaquete = "NOT ASSIGNED";
    }
    else if (packet_protocol == 253 || packet_protocol == 254) {
        tipoPaquete = "TEST";
    }
    else {
        tipoPaquete = "Unknown";
    }


    wchar_t wtipoPaquete[16]; // Suficientemente grande para "TCP", "UDP" u otros
    mbstowcs(wtipoPaquete, tipoPaquete, sizeof(wtipoPaquete) / sizeof(wchar_t));
    if (payload_ptr && payload_length > 0) {
        string payload_data; // Para almacenar el payload como string hexadecimal
        for (int i = 0; i < payload_length; ++i) {
            snprintf(hexBuffer, sizeof(hexBuffer), "%02X ", payload_ptr[i]); // Convertir a hexadecimal
            payload_data += hexBuffer;
        }

        hexadecimal.push_back(payload_data);
        if (filtro == "udp" || filtro == "tcp" || filtro == "icmp") {

            if (strcmp(tipoPaquete, filtro) == 0) {
                wchar_t buffer[512];
                swprintf(buffer, sizeof(buffer) / sizeof(buffer[0]),
                    L"ID: %d | SRC: %S | DST: %S  | TTL: %d | TOS: %d  | PROTOCOL: %d | PROTO: %s | SPORT: %d | DPORT: %d | FLAGS:  %c  %c  %c  %c  %c  %c  |",
                    packet_id, packet_srcip, packet_dstip, packet_ttl, packet_tos, packet_protocol, wtipoPaquete, src_port, dst_port, syn_flag, ack_flag, urg_flag, fin_flag, rst_flag, psh_flag);
                PostMessage(GetParent(hPacket), WM_UPDATE_LISTBOX, 0, (LPARAM)_wcsdup(buffer)); // Usamos _wcsdup para evitar problemas de puntero.
                int count = SendMessage(hPacket, LB_GETCOUNT, 0, 0);
                SendMessage(hPacket, LB_SETTOPINDEX, count - 1, 0);
            }
            else {
                return;
            }
        }
        else {
            wchar_t buffer[512];
            swprintf(buffer, sizeof(buffer) / sizeof(buffer[0]),
                L"ID: %d | SRC: %S | DST: %S  | TTL: %d | TOS: %d  | PROTOCOL: %d | PROTO: %s | SPORT: %d | DPORT: %d | FLAGS:  %c  %c  %c  %c  %c  %c  |",
                packet_id, packet_srcip, packet_dstip, packet_ttl, packet_tos, packet_protocol, wtipoPaquete, src_port, dst_port, syn_flag, ack_flag, urg_flag, fin_flag, rst_flag, psh_flag);
            PostMessage(GetParent(hPacket), WM_UPDATE_LISTBOX, 0, (LPARAM)_wcsdup(buffer)); // Usamos _wcsdup para evitar problemas de puntero.
            int count = SendMessage(hPacket, LB_GETCOUNT, 0, 0);
            SendMessage(hPacket, LB_SETTOPINDEX, count - 1, 0);
        }
        // Guardar información en el archivo .csv
        fprintf(cvsfile, "%d,%s,%s,%d,%d,%d,%s,%d,%d,|%c|%c|%c|%c|%c|%c|\n", packet_id, packet_srcip, packet_dstip, packet_ttl, packet_tos, packet_protocol, tipoPaquete, src_port, dst_port, syn_flag, ack_flag, urg_flag, fin_flag, rst_flag, psh_flag);
    }
}
// Función principal
int main(int argc, char* argv[]) {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    int i = 0; // Contador de interfaces

    // Buffer para errores y lista de dispositivos
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_if_t* d;

    // Obtener la lista de dispositivos
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error al obtener dispositivos: %s\n", errbuf);
        return 1;
    }

    for (d = alldevs; d != NULL && i < 10; d = d->next) { // Limita a 10 dispositivos

        // Copiar el nombre del dispositivo tal como está
        snprintf(dispositivoSeleccionado[i], sizeof(dispositivoSeleccionado[i]), "%s", d->name);
        snprintf(dispositivoSeleccionadoNombre[i], sizeof(dispositivoSeleccionadoNombre[i]), "%s", d->description);
        i++;
    }

    // Liberar la memoria asignada por pcap_findalldevs
    pcap_freealldevs(alldevs);

    //finaliza la deteccion de interfaces de red -----------------------------------------------------




    //inicio graficos------------------------------------------------------------------------------------
    HINSTANCE hInstance = GetModuleHandle(NULL);

    // Registro de la clase de ventana
    WNDCLASS wc = {};
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 2); // Fondo gris, si es +1 es blanco, etc
    wc.lpszClassName = L"MiClaseDeVentana";       // Nombre de la clase

    if (!RegisterClass(&wc)) {
        MessageBox(NULL, L"Error al registrar la clase de ventana.", L"Error", MB_ICONERROR | MB_OK);
        return 1;
    }

    //Aqui creamos la ventana
    hWnd = CreateWindow(
        L"MiClaseDeVentana",          //Nombre de la clase
        L"Detector de paquetes",     //Nombre de la ventana :O
        WS_OVERLAPPEDWINDOW,         // Estilo de la ventana
        CW_USEDEFAULT, CW_USEDEFAULT, // Posición de la ventana
        1200, 700,                    //Tamaño de la ventana
        NULL, NULL,                  // Sin ventana padre ni menú
        hInstance,                   // Instancia de la aplicación
        NULL                         // Sin parámetros adicionales
    );

    hPacket = CreateWindowEx(WS_EX_CLIENTEDGE, L"LISTBOX", NULL, WS_CHILD | WS_VISIBLE | WS_VSCROLL, 0, 0, 1200, 350, hWnd, (HMENU)3001, hInstance, NULL);
    hProtocolos = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", NULL, ES_MULTILINE | ES_READONLY | WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_AUTOHSCROLL | ES_AUTOVSCROLL, 0, 350, 600, 350, hWnd, (HMENU)3002, hInstance, NULL);
    hVistaPaquete = CreateWindowEx(WS_EX_CLIENTEDGE, L"LISTBOX", NULL, WS_CHILD | WS_VISIBLE | WS_VSCROLL, 600, 350, 600, 350, hWnd, (HMENU)3003, hInstance, NULL);
    hFiltro = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", NULL, WS_CHILD | WS_VISIBLE | ES_AUTOVSCROLL, 200, 0, 800, 25, hWnd, (HMENU)111, hInstance, NULL);
    hBoton = CreateWindowEx(0, L"BUTTON", L"Filtrar", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 1000, 0, 200, 25, hWnd, (HMENU)3, hInstance, NULL);

    if (!hWnd) {
        MessageBox(NULL, L"No jala la ventana :(((((((((", L"Error", MB_ICONERROR | MB_OK);
        return 1;
    }

    // Mostrar y actualizar la ventana
    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    // Bucle de mensajes
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    //final Graficos ---------------------------------------------------------------------------------------

    system("exit");
    return 0;
}

HMENU menuAplicacion() {
    HMENU hMenu = CreateMenu();

    HMENU hFileMenu = CreateMenu();
    AppendMenu(hFileMenu, MF_STRING, 1, L"Abrir");


    return hMenu;
}


char error_buffer[PCAP_ERRBUF_SIZE];
FILE* cvsfile;
const char* device = dispositivoSeleccionado[dispositivoSeleccionadoAux]; // Dispositivo especificado---------------------------------
struct bpf_program bpf;
pcap_t* dev;


LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {

    case WM_SIZE: {
        int width = LOWORD(lParam);
        int heigth = HIWORD(lParam);
        MoveWindow(hFiltro, 0, 0, width - 100, 25, TRUE);
        MoveWindow(hBoton, width - 100, 0, 100, 25, TRUE);
        MoveWindow(hPacket, 0, 25, width, (heigth / 2) - 20, TRUE);
        MoveWindow(hProtocolos, 0, heigth / 2, width / 2, heigth / 2, TRUE);
        MoveWindow(hVistaPaquete, width / 2, heigth / 2, width / 2, heigth / 2, TRUE);
        break;
    }


    case WM_UPDATE_PAYLOAD: {
        SetWindowText(hVistaPaquete, (LPCWSTR)lParam);
        break;
    }

    case WM_UPDATE_LISTBOX: {
        // Actualizar el ListBox con el mensaje recibido
        SendMessage(hPacket, LB_ADDSTRING, 0, lParam);
        break;
    }


    case WM_CREATE: {
        HMENU hMenu = menuAplicacion();
        HMENU hFile = menuAplicacion();
        HMENU hParametros = menuAplicacion();
        HMENU hCaptura = menuAplicacion();

        AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hFile, L"Archivo");
        AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hParametros, L"Parametros");
        AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hCaptura, L"Captura");
        AppendMenu(hFile, MF_STRING, IDM_BTN_GUARDAR, L"Guardar Captura");

        AppendMenu(hCaptura, MF_STRING, IDM_BTN_INICIAR, L"Iniciar");
        AppendMenu(hCaptura, MF_STRING, IDM_BTN_DETENER, L"Detener");

        AppendMenu(hParametros, MF_STRING, IDM_ADAPTADOR_DE_RED, L"Adaptador de red");



        SetMenu(hWnd, hMenu);

        break;
    }

    case WM_COMMAND: {
        switch (LOWORD(wParam)) { // Verifica el comando recibido
        case IDM_BTN_GUARDAR: // Opción "Abrir"
            if (auxDetener == 1) {
                MessageBox(hWnd, L"Se debe de detener la captura", L"Error", MB_OK | MB_ICONERROR);
            }
            else if (auxDetener == 0) {
                MessageBox(hWnd, L"No se han capturado paquetes", L"Error", MB_OK | MB_ICONERROR);
            }
            else
            {
                fclose(cvsfile);
                RenombrarArchivo(hWnd);
            }
            break;




        case IDM_BTN_INICIAR: {
            if (!escojioAdaptador) {
                MessageBox(hWnd, L"No se ha seleccionado ningún dispositivo de red", L"Error", MB_OK | MB_ICONERROR);
            }
            else if (auxDetener == 1) {

            }
            else {
                auxDetener = 1;
                // Crear el hilo para la captura de paquetes
                HANDLE hThread = CreateThread(NULL, 0, [](LPVOID) -> DWORD {
                    SendMessage(hPacket, LB_RESETCONTENT, 0, 0);
                    device = dispositivoSeleccionado[dispositivoSeleccionadoAux];
                    dev = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
                    cvsfile = fopen("captura.csv", "w");
                    if (cvsfile == NULL) {
                        pcap_close(dev);
                        fclose(cvsfile);
                    }
                    if (dev == NULL) {
                        return 1;
                    }
                    fprintf(cvsfile, "ID,SRC,DST,TTL,TOS,num.Protocol,Protocolo,puertoSALIDA,PuertoDestino,FLAGS(TCP)\n");
                    // Sin filtros para capturar todo----------------------------------------------------------
                    if (pcap_compile(dev, &bpf, filters, 0, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
                        return 1;
                    }

                    if (pcap_setfilter(dev, &bpf)) {
                        return 1;
                    }

                    int link_hdr_type = pcap_datalink(dev);

                    switch (link_hdr_type) {
                    case DLT_NULL:
                        link_hdr_length = 4;
                        break;
                    case DLT_EN10MB:
                        link_hdr_length = 14;
                        break;
                    default:
                        link_hdr_length = 0;
                    }
                    if (pcap_loop(dev, 0, call_me, (u_char*)cvsfile)) { // Captura de paquetessssssssssssssssssssssssssss
                        return 1;
                    }
                    }, NULL, 0, NULL);

                if (hThread == NULL) {
                    MessageBox(hWnd, L"Error al crear el hilo", L"Error", MB_OK | MB_ICONERROR);
                }
                else {
                    SetThreadPriority(hThread, THREAD_PRIORITY_HIGHEST);
                    CloseHandle(hThread); // Cerramos el handle del hilo, no lo necesitamos
                }
            }
            break;
        } //esto es lo del hilo


        case 3:
            GetWindowTextA(hFiltro, filtro, sizeof(filtro)); // Mostrar el texto para verificar 
            filters = filtro;
            pcap_breakloop(dev);
            auxDetener = 2;
            if (dev) {
                pcap_close(dev);
                dev = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
                if (pcap_compile(dev, &bpf, filters, 0, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
                    MessageBoxA(hWnd, "El filtro ingresado es erroneo", "Error Filtro", MB_OK);
                    SetWindowText(GetDlgItem(hWnd, 111), L"");
                    GetWindowTextA(hFiltro, filtro, sizeof(filtro)); // Mostrar el texto para verificar 
                }
                if (pcap_setfilter(dev, &bpf) == PCAP_ERROR) {
                    MessageBoxA(hWnd, "Error al aplicar el filtro", "Error", MB_OK);
                    SetWindowText(GetDlgItem(hWnd, 111), L"");
                    GetWindowTextA(hFiltro, filtro, sizeof(filtro));
                }

            }
            else {
                MessageBoxA(hWnd, " Todavía no se ha iniciado alguna captura", "ERROR AL FILTRAR", MB_OK);
                SetWindowText(GetDlgItem(hWnd, 111), L"");
                GetWindowTextA(hFiltro, filtro, sizeof(filtro)); // Mostrar el texto para verificar 
            }
            break;
        case 3001: {
            // Obtener el índice del elemento seleccionado
            UpdateWindow(hVistaPaquete);
            int indiceSeleccionado = SendMessage(hPacket, LB_GETCURSEL, 0, 0);
            UpdateWindow(hVistaPaquete);


            if (indiceSeleccionado != LB_ERR) { // Verificar si se seleccionó algo
                SendMessage(hVistaPaquete, LB_RESETCONTENT, 0, 0);

                wstring datoSeleccionado = stringToWString(hexadecimal[indiceSeleccionado]);
                const size_t MAX_LINE_LENGTH = 70;
                for (size_t i = 0; i < datoSeleccionado.size(); i += MAX_LINE_LENGTH) {
                    wstring fragmento = datoSeleccionado.substr(i, MAX_LINE_LENGTH);
                    SendMessage(hVistaPaquete, LB_ADDSTRING, 0, (LPARAM)fragmento.c_str());
                }

                UpdateWindow(hVistaPaquete);
            }
            else {

            }

            break;
        }

        case 3003: {
            // Actualizar la ventana
            UpdateWindow(hProtocolos);

            int indiceSeleccionado = SendMessage(hPacket, LB_GETCURSEL, 0, 0);

            if (indiceSeleccionado != LB_ERR) { // Verificar si se seleccionó algo

                // Limpiar la consola
                system("cls");

                // Obtener la cadena hexadecimal del vector
                string hexCadena = hexadecimal[indiceSeleccionado];

                // Crear un stringstream para separar los valores hexadecimales
                stringstream ss(hexCadena);
                string hexPair;
                string textoTraducido;

                int contadorCaracteres = 0; // Contador para los caracteres

                // Recorrer los pares hexadecimales
                while (ss >> hexPair) {
                    // Convertir el par hexadecimal a un valor decimal
                    int decimalValue = stoi(hexPair, nullptr, 16);

                    // Convertir el valor decimal a un carácter ASCII
                    char charValue = static_cast<char>(decimalValue);

                    // Si el carácter es imprimible o un carácter extendido, lo agregamos directamente
                    if (decimalValue >= 32 && decimalValue <= 126) {
                        textoTraducido += charValue;
                    }
                    else {
                        textoTraducido += '.'; // Reemplazar caracteres no imprimibles con un punto
                    }

                    // Incrementar el contador de caracteres
                    contadorCaracteres++;

                    // Verificar si se han agregado 70 caracteres
                    if (contadorCaracteres >= 70) {
                        textoTraducido += "\r\n"; // Agregar un salto de línea
                        contadorCaracteres = 0; // Reiniciar el contador
                    }
                }

                // Convertir el texto traducido a wstring para enviarlo a la ventana
                wstring wstr(textoTraducido.begin(), textoTraducido.end());

                // Mostrar el texto traducido en la ventana hProtocolos
                SendMessage(hProtocolos, WM_SETTEXT, 0, (LPARAM)wstr.c_str());
                UpdateWindow(hProtocolos);
            }
            else {
                // Manejo de error si no hay selección
            }
            break;
        }



        case IDM_BTN_DETENER: {
            UpdateWindow(hVistaPaquete);
            if (auxDetener == 0) {
                MessageBox(hWnd, L"No se ha iniciado la captura", L"Error detener", MB_OK | MB_ICONERROR);
            }
            else {
                pcap_breakloop(dev);
                auxDetener = 2;
            }


            break;
        }

        case IDM_ADAPTADOR_DE_RED: { // Ventana "Adaptador de Red"
            WNDCLASS wc = {};
            wc.lpfnWndProc = NuevaVentanaProc;
            wc.hInstance = GetModuleHandle(NULL);
            wc.lpszClassName = L"SeleccionarInterfazVentana";
            wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 2); // Fondo gris

            if (!RegisterClass(&wc)) {
                MessageBox(hWnd, L"Error al registrar la ventana", L"Error", MB_OK | MB_ICONERROR);
                break;
            }

            HWND hSeleccionarInterfazVentana = CreateWindow(
                L"SeleccionarInterfazVentana",
                L"Ventana Adaptador de Red",
                WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT, CW_USEDEFAULT,
                900, 600,
                hWnd,
                NULL,
                GetModuleHandle(NULL),
                NULL);

            if (hSeleccionarInterfazVentana) {
                ShowWindow(hSeleccionarInterfazVentana, SW_SHOW);
                UpdateWindow(hSeleccionarInterfazVentana);
            }
            else {
                MessageBox(hWnd, L"Error al crear la ventana", L"Error", MB_OK | MB_ICONERROR);
            }
            break;
        }
                                 // Otros casos de WM_COMMAND
        }
        UpdateWindow(hVistaPaquete);
        break;
    }




    case WM_DESTROY:
        system("exit");
        PostQuitMessage(0); // Cerrar la aplicación
        break;

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

LRESULT CALLBACK NuevaVentanaProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    static HWND hListBox = NULL;

    switch (message) {
    case WM_CREATE:
        // Crear el control de lista (List Box)
        hListBox = CreateWindowEx(
            0,                           // Estilo extendido
            L"LISTBOX",                   // Clase del control
            NULL,                         // Sin título
            WS_CHILD | WS_VISIBLE | WS_BORDER | LBS_STANDARD, // Estilos del List Box
            45, 30,                       // Posición en la ventana
            800, 500,                     // Tamaño (ancho x alto)
            hWnd,                         // Ventana principal (padre)
            (HMENU)1,                     // Identificador del control
            GetModuleHandle(NULL),        // Instancia
            NULL);                        // Puntero adicional (NULL)



        for (int i = 0; i < 10; ++i) {
            // Convertir char a LPWSTR (Wide String) para usar en el ListBox
            wchar_t nombreRed[80];
            mbstowcs(nombreRed, dispositivoSeleccionadoNombre[i], 80); // Convierte char a wide string (Unicode)

            // Agregar el nombre al ListBox
            SendMessage(hListBox, LB_ADDSTRING, 0, (LPARAM)nombreRed);
        }

        CreateWindow(
            L"BUTTON", L"Aceptar",         // Tipo de control y título
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON, // Estilos
            747, 530,                       //posicion del boton x,y
            100, 30,                       //tamaño del botón
            hWnd,                         // Ventana principal (padre)
            (HMENU)2,                     // Identificador del botón
            GetModuleHandle(NULL),        // Instancia
            NULL);                        // Puntero adicional (NULL)
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == 2) { // Si el botón "Aceptar" fue presionado
            // Obtener el índice del dispositivo seleccionado
            dispositivoSeleccionadoAux = SendMessage(hListBox, LB_GETCURSEL, 0, 0);
            escojioAdaptador = true;
            // Si se seleccionó un dispositivo válido (LB_ERR si no se seleccionó nada)
            if (dispositivoSeleccionadoAux != LB_ERR) {


            }
            else {
                // Si no se ha seleccionado un dispositivo
                MessageBox(hWnd, L"No seleccionaste ningun dispositivo de red >:(", L">:(", MB_OK | MB_ICONERROR);
                dispositivoSeleccionadoAux = dispositivoSeleccionadoAux + 1;
            }

            // Cerrar la ventana secundaria
            PostMessage(hWnd, WM_CLOSE, 0, 0);
        }



        break;



    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}