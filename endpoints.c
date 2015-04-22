/*
 * Copyright (C) 2015 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 * @brief       microcoap server endpoints
 * 
 * @author      Jori Winderickx <jori.winderickx@student.uhasselt.be>
 * @author      Original: Lotte Steenbrink 
 *
 * @}
 */

#include <stdbool.h>
#include <stdbool.h>
#include <string.h>
#include "coap.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#define MAX_RESPONSE_LEN 1500
static uint8_t response[MAX_RESPONSE_LEN] = "";

static const coap_endpoint_path_t path_lights = {1, {"lights"}};
static const coap_endpoint_path_t path_certificate = {1, {"certificate"}};

int lights[5]; //TODO: make hardware light!

void create_response_payload(const uint8_t *buffer)
{
    char *response = "1337";
    memcpy((void*)buffer, response, strlen(response));
}

/* The handler which handles the path /lights/ */
static int handle_put_light(coap_rw_buffer_t *scratch, const coap_packet_t *inpkt, coap_packet_t *outpkt, uint8_t id_hi, uint8_t id_lo)
{
    if (inpkt->payload.len == 0)
        return coap_make_response(scratch, outpkt, NULL, 0, id_hi, id_lo, &inpkt->tok, COAP_RSPCODE_BAD_REQUEST, COAP_CONTENTTYPE_TEXT_PLAIN);
    if (sizeof(inpkt->payload.p[0]) > 0 && sizeof(inpkt->payload.p[1]) > 0)
    {
        lights[inpkt->payload.p[0]] = inpkt -> payload.p[1];
        //TODO: change hardware light instead of variable
         
        return coap_make_response(scratch, outpkt, (const uint8_t *)&lights[inpkt->payload.p[0]], 1, id_hi, id_lo, &inpkt->tok, COAP_RSPCODE_CHANGED, COAP_CONTENTTYPE_TEXT_PLAIN);
    }
    return coap_make_response(scratch, outpkt, NULL, 0, id_hi, id_lo, &inpkt->tok, COAP_RSPCODE_BAD_REQUEST, COAP_CONTENTTYPE_TEXT_PLAIN);
    
}

/* The handler which handles the path /certificate/ */
static int handle_put_certificate(coap_rw_buffer_t *scratch, const coap_packet_t *inpkt, coap_packet_t *outpkt, uint8_t id_hi, uint8_t id_lo)
{
   if (inpkt->payload.len == 0){
      return coap_make_response(scratch, outpkt, NULL, 0, id_hi, id_lo, &inpkt->tok, COAP_RSPCODE_BAD_REQUEST, COAP_CONTENTTYPE_TEXT_PLAIN);
   }
   
   //TODO: set certificate
   return coap_make_response(scratch, outpkt, (const uint8_t *)&"Ok", 1, id_hi, id_lo, &inpkt->tok, COAP_RSPCODE_CHANGED, COAP_CONTENTTYPE_TEXT_PLAIN);
    
}

/* The handler which handles the path /lights/id */
static int handle_get_light(coap_rw_buffer_t *scratch, const coap_packet_t *inpkt, coap_packet_t *outpkt, uint8_t id_hi, uint8_t id_lo)
{
    DEBUG("[endpoints]  %s()\n",  __func__);
    if (inpkt->payload.len == 0){
      return coap_make_response(scratch, outpkt, NULL, 0, id_hi, id_lo, &inpkt->tok, COAP_RSPCODE_BAD_REQUEST, COAP_CONTENTTYPE_TEXT_PLAIN);
    }
    //TODO: retrieve real light from hardware of something
    int var = lights[inpkt->payload.p[0]];
    response[sizeof(var)-0] = (uint8_t)var;
    create_response_payload(response);
    
    return coap_make_response(scratch, outpkt, response, strlen((char*)response),
                              id_hi, id_lo, &inpkt->tok, COAP_RSPCODE_CONTENT, COAP_CONTENTTYPE_TEXT_PLAIN);
}

const coap_endpoint_t endpoints[] =
{
    {COAP_METHOD_PUT, handle_put_light, &path_lights, "ct=0"},
    {COAP_METHOD_GET, handle_get_light, &path_lights, "ct=0"},
    {COAP_METHOD_PUT, handle_put_certificate, &path_certificate, "ct=0"},
    {(coap_method_t)0, NULL, NULL, NULL} /* marks the end of the endpoints array */
};
