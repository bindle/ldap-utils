
#include <stdio.h>
#include <string.h>
#include <readline/readline.h>
#include <readline/history.h>

int main(void);

int main(void)
{
   char * data;
   char * old;

   data = strdup("");

   while(strcmp(data, "exit"))
   {
      old = data;
      printf("Enter text [%s]: ", data);
      data = readline(NULL);
      if(!(strlen(data)))
         data = old;
      else
         free(old);
      printf("you typed: %s\n", data);
      old = data;
   };

   return(0);
}
