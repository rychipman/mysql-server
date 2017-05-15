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
static int mongosql_auth(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql)
{

  // TODO: read plugin name?

  /* read auth-data */
  unsigned char *pkt;
  int pkt_len;
  pkt_len = vio->read_packet(vio, &pkt);
  if (pkt_len < 0) {
    fprintf(stderr, "ERROR: failed while reading auth-data from initial handshake\n");
    return CR_ERROR;
  }

  /* parse the contents of auth-data */
  uint8_t major_version;
  uint8_t minor_version;
  memcpy(&major_version, pkt, 1);
  memcpy(&minor_version, pkt+1, 1);
  fprintf(stderr, "received auth-data from server (%d bytes)\n", pkt_len);
  fprintf(stderr, "    major_version: %d\n", major_version);
  fprintf(stderr, "    minor_version: %d\n", minor_version);

  /* write 0 bytes */
  if (vio->write_packet(vio, (const unsigned char *) "", 1)) {
    fprintf(stderr, "ERROR: failed while writing zero-byte response\n");
    return CR_ERROR;
  }
  fprintf(stderr, "sent empty handshake response\n");

  /* first auth-more-data */
  pkt_len = vio->read_packet(vio, &pkt);
  if (pkt_len < 0) {
    fprintf(stderr, "ERROR: failed while reading first auth-more-data\n");
    return CR_ERROR;
  }

  unsigned char *mechanism;
  uint32_t num_conversations;
  mechanism = pkt;
  memcpy(&num_conversations, pkt+strlen((const char *)mechanism)+1, 4);
  fprintf(stderr, "received first auth-more-data (%d bytes)\n", pkt_len);
  fprintf(stderr, "    mechanism: '%s'\n", mechanism);
  fprintf(stderr, "    num_conversations: %d\n", num_conversations);


   mongoc_scram_t scram;
   _mongoc_scram_init (&scram);
   _mongoc_scram_set_pass (&scram, mysql->passwd);
   _mongoc_scram_set_user (&scram, mysql->user);

   fprintf(stderr, "initialized scram\n");
   fprintf(stderr, "    user: %s\n", mysql->user);
   fprintf(stderr, "    pass: %s\n", mysql->passwd);

   unsigned char scram_outbuf[4096] = {0};
   uint32_t scram_outbuf_len = 0;

   unsigned char *scram_inbuf = scram_outbuf;
   uint32_t scram_inbuf_len = 0;

   my_bool success;

   for (;;) {

       for(unsigned int conv = 0; conv < num_conversations; conv++) {

          bson_error_t error;
          success = _mongoc_scram_step (
                  &scram,
                  scram_inbuf,
                  scram_inbuf_len,
                  scram_outbuf,
                  sizeof scram_outbuf,
                  &scram_outbuf_len,
                  &error
          );
          if (!success) {
             goto failure;
          }

           scram_inbuf += scram_inbuf_len;
           memcpy(&scram_inbuf_len, scram_inbuf, 4);
           scram_inbuf += 4;
       }

      uint32_t payload_len = scram_outbuf_len;
      uint32_t conversation_len = payload_len + 5;
      uint32_t data_len = conversation_len * num_conversations;
      uint8_t complete = 0;
      unsigned char *data = malloc(data_len);
      memcpy(data, &complete, 1);
      memcpy(data+1, &payload_len, 4);
      memcpy(data+5, scram_outbuf, payload_len);
      memcpy(data+conversation_len, data, conversation_len);

      if (vio->write_packet(vio, data, data_len)) {
          fprintf(stderr, "ERROR: failed while writing scram step %d\n", scram.step);
          return CR_ERROR;
      }

      fprintf(stderr, "sent scram step %d\n", scram.step);
      unsigned char *conversation = data;
      for(unsigned int i=0; i<num_conversations; i++) {
          fprintf(stderr, "    conversation: %d\n", i);
          fprintf(stderr, "        length: %d\n", conversation_len);
          fprintf(stderr, "        complete: %d\n", complete);
          fprintf(stderr, "        payload_len: %d\n", payload_len);
          fprintf(stderr, "        payload: '%s'\n", conversation+5);
          conversation += conversation_len;
      }

      /* read server reply */
      unsigned char *pkt;
      int pkt_len;
      pkt_len = vio->read_packet(vio, &pkt);
      if (pkt_len < 0) {
        fprintf(stderr, "ERROR: failed while reading server reply to scram step %d\n", scram.step);
        return CR_ERROR;
      }
      fprintf(stderr, "received scram step %d response\n", scram.step);
      fprintf(stderr, "    length: %d\n", pkt_len);
      fprintf(stderr, "    content: '%s'\n", pkt);

       scram_inbuf = pkt + 4;
       memcpy(&scram_inbuf_len, pkt, 4);
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
