
int64_t
bson_ascii_strtoll (const char *s, char **e, int base)
{
   char *tok = (char *) s;
   char *digits_start;
   char c;
   int64_t number = 0;
   int64_t sign = 1;
   int64_t cutoff;
   int64_t cutlim;

   errno = 0;

   if (!s) {
      errno = EINVAL;
      return 0;
   }

   c = *tok;

   while (isspace (c)) {
      c = *++tok;
   }

   if (c == '-') {
      sign = -1;
      c = *++tok;
   } else if (c == '+') {
      c = *++tok;
   } else if (!isdigit (c)) {
      errno = EINVAL;
      return 0;
   }

   /* from here down, inspired by NetBSD's strtoll */
   if ((base == 0 || base == 16) && c == '0' &&
       (tok[1] == 'x' || tok[1] == 'X')) {
      tok += 2;
      c = *tok;
      base = 16;
   }

   if (base == 0) {
      base = c == '0' ? 8 : 10;
   }

   /* Cutoff is the greatest magnitude we'll be able to multiply by base without
    * range error. If the current number is past cutoff and we see valid digit,
    * fail. If the number is *equal* to cutoff, then the next digit must be less
    * than cutlim, otherwise fail.
    */
   cutoff = sign == -1 ? INT64_MIN : INT64_MAX;
   cutlim = (int) (cutoff % base);
   cutoff /= base;
   if (sign == -1) {
      if (cutlim > 0) {
         cutlim -= base;
         cutoff += 1;
      }
      cutlim = -cutlim;
   }

   digits_start = tok;

   while ((c = *tok)) {
      if (isdigit (c)) {
         c -= '0';
      } else if (isalpha (c)) {
         c -= isupper (c) ? 'A' - 10 : 'a' - 10;
      } else {
         /* end of number string */
         break;
      }

      if (c >= base) {
         break;
      }

      if (sign == -1) {
         if (number < cutoff || (number == cutoff && c > cutlim)) {
            number = INT64_MIN;
            errno = ERANGE;
            break;
         } else {
            number *= base;
            number -= c;
         }
      } else {
         if (number > cutoff || (number == cutoff && c > cutlim)) {
            number = INT64_MAX;
            errno = ERANGE;
            break;
         } else {
            number *= base;
            number += c;
         }
      }

      tok++;
   }

   /* did we parse any digits at all? */
   if (e != NULL && tok > digits_start) {
      *e = tok;
   }

   return number;
}


