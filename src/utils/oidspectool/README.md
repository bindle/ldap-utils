This is a simple parser which combines OID specifications from inidividual
files into a single source file containing a sorted array of OID
specificications. The alternative was to manually maintain a monolithic list
of OID specifications in a single source file. Full disclaimer, I was
recovering from treatment of Alemtuzumab when I learned Lex/Yacc and wrote
this utility. So if this utility automates the OID maintenance and reduces
errors in the specification, GREAT!!  If not, at least focusing on this
project kept the world from spinning around me as lymphocytes smuggling CD52
were exterminated by monoclonal antibodies roaming my bloodstream.

Bread Crumbs:

   * Tutorial on lex/yacc by Jonathan Engelsma
     - [Part 01: Tutorial on lex/yacc](https://www.youtube.com/watch?v=54bo1qaHAfk) [(source code)](https://github.com/jengelsma/lex-tutorial)
     - [Part 02: Tutorial on lex/yacc.](https://www.youtube.com/watch?v=__-wUHG2rfM) [(source code)](https://github.com/jengelsma/yacc-tutorial)

   * [Lex and YACC primer/HOWTO](http://tldp.org/HOWTO/Lex-YACC-HOWTO-6.html#ss6.2)

   * [Automake: Yacc and Lex support](https://www.gnu.org/software/automake/manual/html_node/Yacc-and-Lex.html)

