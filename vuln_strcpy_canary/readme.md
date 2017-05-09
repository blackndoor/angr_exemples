# strcpy - source buffer / offset before canary

It's the same base script and binary as [vuln_strcpy](https://github.com/blackndoor/angr/tree/master/vuln_strcpy) exemple + a check to find if __stack_chk_fail is present and if we can overflow the canary with the source buffer.
