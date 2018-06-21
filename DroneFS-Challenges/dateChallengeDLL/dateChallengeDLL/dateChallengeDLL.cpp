#include "dateChallengeDLL.h"

using namespace rapidxml;



DATECHALLENGEDLL_API PUCHAR execute(PUCHAR* parametrosXml) {

	

	//A partir de aqui es propio del challenge de Fecha

	int min = std::stoi((PCHAR)parametrosXml[0]);
	int max = std::stoi((PCHAR)parametrosXml[1]);
	int mask = std::stoi((PCHAR)parametrosXml[2]);

	std::locale loc;
	const std::time_get<char>& tmget_hoy = std::use_facet <std::time_get<char> >(loc);

	char* dateHoySafePchar = (PCHAR)malloc(10 + 1);
	
	PUCHAR* paramEntornoPUCHAR = getChallengeUnProtectParams();

	PUCHAR dateHoyPuchar = paramEntornoPUCHAR[0];

	char* dateHoyPchar = (PCHAR)dateHoyPuchar;

	size_t dateHoyLength = strlen(dateHoyPchar);

	memcpy(dateHoySafePchar, dateHoyPchar, dateHoyLength);
	dateHoySafePchar[dateHoyLength] = 0;
	//dateHoyPchar[strlen(dateHoyPchar)] = 0;

	std::string dateHoy(dateHoySafePchar);

	std::ios::iostate state;
	std::istringstream iss_hoy(dateHoy);
	std::tm hoy;

	tmget_hoy.get_date(iss_hoy, std::time_get<char>::iter_type(), iss_hoy, state, &hoy);

	//Suma que equivale a concatenar los valores de la fecha
	int suma_hoy = hoy.tm_year * 10000 + hoy.tm_mon * 100 + hoy.tm_mday;

	int parte_comun = suma_hoy >> mask;

	std::string resultado = "";

	//Comparador de fecha
	int final_hoy = suma_hoy & (0xFFFFFFFF >> (32 - mask));

	if ((final_hoy >= min) && (final_hoy <= max))
	{
		//String que devuelve el challenge
		resultado = std::to_string(parte_comun);
	}
	PUCHAR challReturn = (PUCHAR)_strdup(resultado.c_str());
	return challReturn;
}

DATECHALLENGEDLL_API PUCHAR* executeParam() {


	//PUCHAR* fechaDesdePUCHAR = getChallengeProtectParams();
	//PUCHAR* fechaHastaPUCHAR = getChallengeProtectParams();
	

	PUCHAR* paramEntornoPUCHAR = getChallengeProtectParams();

	PUCHAR dateDesdePuchar = paramEntornoPUCHAR[0];
	PUCHAR dateHastaPuchar = paramEntornoPUCHAR[1];

	std::string dateDesde((PCHAR)dateDesdePuchar);
	std::string dateHasta((PCHAR)dateHastaPuchar);

	std::locale loc;
	const std::time_get<char>& tmget_inicio = std::use_facet <std::time_get<char> >(loc);
	const std::time_get<char>& tmget_limite = std::use_facet <std::time_get<char> >(loc);
	const std::time_get<char>& tmget_fuera = std::use_facet <std::time_get<char> >(loc);

	std::ios::iostate state;
	std::istringstream iss_inicio(dateDesde);
	std::istringstream iss_limite(dateHasta);
	std::tm inicio, limite;

	tmget_inicio.get_date(iss_inicio, std::time_get<char>::iter_type(), iss_inicio, state, &inicio);
	tmget_limite.get_date(iss_limite, std::time_get<char>::iter_type(), iss_limite, state, &limite);

	//Suma que equivale a concatenar los valores de la fecha
	int suma_inicio = inicio.tm_year * 10000 + inicio.tm_mon * 100 + inicio.tm_mday;
	int suma_limite = limite.tm_year * 10000 + limite.tm_mon * 100 + limite.tm_mday;
	int suma_fuera = limite.tm_year * 10000 + limite.tm_mon * 100 + (limite.tm_mday + 1);


	//Saco XOR entre fecha inicio y limite
	uint32_t xor_inicio_limite = suma_inicio ^ suma_limite;

	//Buscar el bit a 1 mas significativo (para coger la parte comun como clave de cifrado)
	int posicion = 0;
	for (int i = 0; i < 32; i++) {

		if (xor_inicio_limite & (0x80000000 >> i))
		{
			posicion = i;
			break;
		}
	}

	int parte_comun = suma_limite >> (32 - posicion);

	//String que devuelve el challenge
	std::string resultado = std::to_string(parte_comun);

	//Setters para el .SAD
	int inicio_xml = suma_inicio & (0xFFFFFFFF >> posicion);
	int final_xml = suma_limite & (0xFFFFFFFF >> posicion);
	int numBitsMask_xml = 32 - posicion;

	//Creamos los returns. El resultado del challenge y el xml para incluir en el .sad

	std::string xml_return = std::string("<param>") + std::to_string(inicio_xml) +
		std::string("</param><param>") + std::to_string(final_xml) + std::string("</param><param>") +
		std::to_string(numBitsMask_xml) + std::string("</param>");


	PUCHAR* challengeReturn = new UCHAR *[2];
	challengeReturn[0] = (PUCHAR)_strdup(resultado.c_str());

	char* firstPartXml = "<Challenge name=\"dateChallenge\">\
		<Params nparams=\"3\">";
	char* midPartXml = _strdup(xml_return.c_str());
	char* finalPartXml = "</Params>\
		</Challenge>";

	char* xmlReturn;
	xmlReturn = (PCHAR)malloc(strlen(firstPartXml) + strlen(midPartXml) + strlen(finalPartXml));

	strcpy(xmlReturn, firstPartXml); /* copy name into the new var */
	strcat(xmlReturn, midPartXml); /* add the extension */
	strcat(xmlReturn, finalPartXml); /* add the extension */

	challengeReturn[1] = (PUCHAR)xmlReturn;

	return challengeReturn;
}

PUCHAR* getChallengeProtectParams() {
	time_t rawtime;
	struct tm * timeinfo;
	char bufferDesde[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(bufferDesde, sizeof(bufferDesde), "%d/%m/%Y", timeinfo);


	std::ifstream file("C:\\W10 PC\\Projects\\DroneFSfilter\\x64\\Debug\\dronefsconfig.txt");
	std::string textcontent((std::istreambuf_iterator<char>(file)),
		std::istreambuf_iterator<char>());

	std::string xmlDroneFS = textcontent;
	std::vector<char> xml_copy(xmlDroneFS.begin(), xmlDroneFS.end());
	xml_copy.push_back('\0');
	xml_document<> doc;
	doc.parse<0>(&xml_copy[0]);
	xml_node<>* top_node = NULL;
	xml_node<>* cipher_node = NULL;
	xml_node<>* chall_node = NULL;
	int numChallenges = 0;


	top_node = doc.first_node("DroneFSConfig");
	top_node = top_node->first_node("CipherData");
	chall_node = top_node->next_sibling("Challenges");

	chall_node = chall_node->first_node("count");
	numChallenges = atoi(chall_node->value());


	for (int i = 0; i < numChallenges; i++) {
		chall_node = chall_node->next_sibling("Challenge");
		char* challNodeName = chall_node->first_attribute("name")->value();
		if (strcmp(challNodeName, "dateChallenge") == 0) {
			chall_node = chall_node->first_node("Params");
			int numParams = atoi(chall_node->first_attribute("nparams")->value());
			if (numParams != 0) {
				char** dllParamList = new char *[numParams];
				chall_node = chall_node->first_node("param");
				char* temp = chall_node->value();
				dllParamList[0] = new char[strlen(temp) + 1];
				memcpy(dllParamList[0], temp, strlen(temp) + 1);

				time_t hastaRawTime = AddMonths_OracleStyle(rawtime, atoi(dllParamList[0]));
				struct tm * hastatimeinfo;
				char bufferHasta[80];

				hastatimeinfo = localtime(&hastaRawTime);

				strftime(bufferHasta, sizeof(bufferHasta), "%d/%m/%Y", hastatimeinfo);

				char* bufferDesdePchar = &bufferDesde[0];
				char* bufferHastaPchar = &bufferHasta[0];

				bufferDesdePchar[strlen(bufferDesdePchar)] = 0;
				bufferHastaPchar[strlen(bufferHastaPchar)] = 0;

				PUCHAR bufferDesdePuchar = (PUCHAR)bufferDesdePchar;
				PUCHAR bufferHastaPuchar = (PUCHAR)bufferHastaPchar;

				PUCHAR* envParams = new UCHAR *[2];

				envParams[0] = bufferDesdePuchar;
				envParams[1] = bufferHastaPuchar;
				return envParams;
			}
		}
	}
	return 0;

}

PUCHAR* getChallengeUnProtectParams() {

	time_t rawtime;
	struct tm * timeinfo;
	char bufferDesde[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(bufferDesde, sizeof(bufferDesde), "%d/%m/%Y", timeinfo);

	char* bufferDesdePchar = &bufferDesde[0];

	bufferDesdePchar[strlen(bufferDesdePchar)] = 0;

	PUCHAR bufferDesdePuchar = (PUCHAR)bufferDesdePchar;
	
	PUCHAR* envParams = new UCHAR *[1];
	envParams[0] = bufferDesdePuchar;
	return envParams;
}

bool IsLeapYear(int year)
{
	if (year % 4 != 0) return false;
	if (year % 400 == 0) return true;
	if (year % 100 == 0) return false;
	return true;
}

int daysInMonths[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

int GetDaysInMonth(int year, int month)
{
	assert(month >= 0);
	assert(month < 12);

	int days = daysInMonths[month];

	if (month == 1 && IsLeapYear(year)) // February of a leap year
		days += 1;

	return days;
}

tm AddMonths_OracleStyle(const tm &d, int months)
{
	bool isLastDayInMonth = d.tm_mday == GetDaysInMonth(d.tm_year, d.tm_mon);

	int year = d.tm_year + months / 12;
	int month = d.tm_mon + months % 12;

	if (month > 11)
	{
		year += 1;
		month -= 12;
	}

	int day;

	if (isLastDayInMonth)
		day = GetDaysInMonth(year, month); // Last day of month maps to last day of result month
	else
		day = min(d.tm_mday, GetDaysInMonth(year, month));

	tm result = tm();

	result.tm_year = year;
	result.tm_mon = month;
	result.tm_mday = day;

	result.tm_hour = d.tm_hour;
	result.tm_min = d.tm_min;
	result.tm_sec = d.tm_sec;

	return result;
}

time_t AddMonths_OracleStyle(const time_t &date, int months)
{
	tm d = tm();

	localtime_s(&d, &date);

	tm result = AddMonths_OracleStyle(d, months);

	return mktime(&result);
}