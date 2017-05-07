# strcpy - source buffer / offset before canary

It's the same base script as the first strcpy exemple + a check to find if __stack_chk_fail is present and if we can overflow the canary with the source buffer.
