#define  _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>
#include <string.h>
#include <crypt.h>
#include <malloc.h>

char* getInteresting(char* url) { //Extract the passwords from the input file
    int i = 0;
    for (i=0;i<strlen(url) - 1;i++) {
        if (url[i] == '\t') {
            int len = strlen(url) - i;
            char* copy = (char*)malloc(len + 1);
            strcpy(copy, url + i+1);
            return copy;  
            free(copy);
        }
    }
    return 0;
}

void chomp(char *s) { //Chomp away carriage return, newline and elements that aren't in passwords' characteristics
  regex_t regex;
  regcomp(&regex,"[a-zA-Z0-9*_]",0);
  while(*s && *s != '\n' && *s != '\r' && regexec(&regex, s, 0, NULL, 0) == 0) s++;
  *s = 0;
}

int main(int argc, char *argv[])
{
  FILE *file, *filew, *filed;
  char *line = NULL;
  char *linew = NULL;
  char *lined = NULL;
  char salt[6];
  size_t len = 0;
  size_t lenw = 0;
  size_t lend = 0;
  size_t lens = 0;
  file=fopen(argv[1], "r"); //Read in shadow file
  filew = fopen("pink.txt", "w+");  //Placeholder for password
  filed = fopen("dict.txt", "r"); //Dictionary corpus

  if (argc < 2) {
    fprintf(stderr, "usage: %s <filename>\n", argv[0]);
    exit(1);
  }
  if (file == NULL){
    printf("Error while opening the file.\n");
    exit(1);
  }

  while ((getline(&line, &len, file)) != -1) { //Passwords preprocessing
    fprintf(filew, "%s", getInteresting(line));
  }

  rewind(filew);  //Reset placeholder pointer 
  ssize_t readw = getline(&linew, &lenw, filew);  //# of lines in placeholder
  ssize_t readd = getline(&lined, &lend, filed);  //# of lines in dictionary
  do {
    readw++;
    sprintf(salt, "%.2s", linew); //Password's first 2 elements to salt
    do {
      readd++;
      chomp(lined);
      chomp(linew);
      if (strcmp(linew, crypt(lined, salt)) == 0){  //Match passwords with precompute dictionary
        printf("Password: %s \nDecryption: %s\n\n", crypt(lined, salt), lined);
      }
      readd = getline(&lined, &lend, filed);  //next line
    } while (readd >= 0);
    rewind(filed);  //Reset dictionary pointer
    readw = getline(&linew, &lenw, filew);  //next line
  } while (readw >= 0);

  free(line);
  free(linew);
  free(lined);
  fclose(file);
  fclose(filew);
  fclose(filed);
  return 0;
}
