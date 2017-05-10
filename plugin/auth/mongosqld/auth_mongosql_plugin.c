/*
 * Copyright 2017 MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <my_global.h>
#include <mysql/plugin_auth.h>
#include <mysql/client_plugin.h>
#include <mysql/service_my_plugin_log.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <mysql.h>
#include "bson.h"
#include "mongoc-error.h"
#include "mongoc-scram.c"

#define MAX_MECHANISM_LENGTH 1024

/**
  Authenticate the client using the MongoDB MySQL Authentication Plugin Protocol.
 
  @param vio Provides plugin access to communication channel
  @param mysql Client connection handler

  @return Error status
    @retval CR_ERROR An error occurred.
    @retval CR_OK Authentication succeeded.
*/
static int mongosql_auth(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
  mongoc_scram_t scram;
  const char *auth_source;
  unsigned char *pkt;
  int pkt_len;

  unsigned char *mechanism;
  int32_t num_conversations;

  // TODO: read plugin name?

  /* read auth-data */
  pkt_len = vio->read_packet(vio, &pkt)
  if (pkt_len < 0) {
    return CR_ERROR;
  }
  // TODO: parse the contents of this message
  int8_t major_version = *(int8_t*)pkt;
  int8_t minor_version = *(int8_t*)(pkt+sizeof(pkt));
  fprintf(stderr, "received auth-data from server (%d bytes)\n", pkt_len);
  fprintf(stderr, "    major_version: %d\n", major_version);
  fprintf(stderr, "    minor_version: %d\n", minor_version);

  /* write 0 bytes */
  if (vio->write_packet(vio, (const unsigned char *) "", 1)) {
    return CR_ERROR;
  }
  fprintf(stderr, "sent empty handshake response\n");

  /* first auth-more-data */
  pkt_len= vio->read_packet(vio, &pkt)
  if (pkt_len < 0) {
    return CR_ERROR;
  }
  mechanism = pkt;
  memcpy(&num_conversations, pkt+strlen((const char *)mechanism)+1, 4);
  fprintf(stderr, "received first auth-more-data (%d bytes)\n", pkt_len);
  fprintf(stderr, "    mechanism: '%s'\n", mechanism);
  fprintf(stderr, "    num_conversations: %d\n", num_conversations);

   /*
   if (!(auth_source = mongoc_uri_get_auth_source (cluster->uri)) ||
       (*auth_source == '\0')) {
      auth_source = "admin";
   }
   */
   auth_source = "admin";

   _mongoc_scram_init (&scram);

   /*
   _mongoc_scram_set_pass (&scram, mongoc_uri_get_password (cluster->uri));
   _mongoc_scram_set_user (&scram, mongoc_uri_get_username (cluster->uri));
   */

   _mongoc_scram_set_pass (&scram, info->auth_string);
   _mongoc_scram_set_user (&scram, info->user_name);

   uint32_t buflen = 0;
   unsigned char buf[4096] = {0};
   for (;;) {
      bson_error_t error;
      if (!_mongoc_scram_step (&scram, buf, buflen, buf, sizeof buf, &buflen, &error)) {
         goto failure;
      }

      unsigned char *char_buf = (unsigned char *) buf;
      int32_t payload_len = strlen(char_buf);
      int32_t data_len = payload_len + 5;
      unsigned char *data = malloc(data_len);
      *data = (const char *)"0";
      memcpy(data+8, &payload_len, 32);
      memcpy(data+40, char_buf, strlen(char_buf));

      if (vio->write_packet(vio, data, data_len)) {
          return CR_ERROR;
      }
      fprintf(stderr, "sent scram step %d\n", scram.step);
      fprintf(stderr, "    length: %d\n", data_len);
      fprintf(stderr, "    payload: '%s'\n", data+40);

      /* read server reply */
      buflen = vio->read_packet(vio, &buf)
      if (buflen < 0) {
        return CR_ERROR;
      }
      fprintf(stderr, "received scram step %d response\n", scram.step);
      fprintf(stderr, "    length: %d\n", buflen);
      fprintf(stderr, "    content: '%s'\n", buf);
   }

   fprintf(stderr, "%s", "SCRAM: authenticated");

failure:
   _mongoc_scram_destroy (&scram);

   return CR_OK;
}


mysql_declare_client_plugin(AUTHENTICATION)
  "mongosql_auth",
  "MongoDB",
  "MongoDB MySQL Authentication Plugin",
  {0,1,0},
  "GPL",
  NULL,
  NULL,
  NULL,
  NULL,
  mongosql_auth
mysql_end_client_plugin;
