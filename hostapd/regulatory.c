/*
 * hostapd / Module short description
 * Copyright (c) 2010, Texas Instruments, Inc. - http://www.ti.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * For more details please review the below BSD terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *  notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name(s) of the above-listed copyright holder(s) nor the
 *  names of its contributors may be used to endorse or promote products
 *  derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** \file regulatory.c
 *  \brief Regulatory domain implementation
 *
 *  \see regulatory.h
 */
#include "includes.h"
#include "hostapd.h"
#include "driver.h"
#include "ieee802_1x.h"
#include "eloop.h"
#include "ieee802_11.h"
#include "sta_info.h"
#include "config.h"
#include "hw_features.h"
#include "APExternalIf.h"
#include "regulatory.h"

/********************************************************************************/
/*						Internal definition.					        		*/
/********************************************************************************/
typedef enum
{
 REG_USA_INDEX,
 REG_JAPAN_INDEX,
 REG_EUROPE_INDEX,
 REG_ALL_INDEX,
 REG_TI_INDEX,
 REG_MAX_INDEX
}ERegIndex;

#define DEFAULT_24_FREQ       2407
#define DEFAULT_5_FREQ        5000

#define MAX_CHAN_NUM            15
#define MAX_CLASS_NUM           10
#define MAX_NUM_OF_REGION        4
#define DBM_TO_TX_POWER_FACTOR  10


static int RateATbl[] = {60};
static int RateGTbl[] = {10,20,55,110,60,90,120,180,240,360,480,540};
static int RateBTbl[] = {10,20,55,110};

typedef enum
{
    DOT11_B_MODE    = 1,
    DOT11_A_MODE    = 2,
    DOT11_G_MODE    = 3,
    DOT11_DUAL_MODE = 4,
    DOT11_N_MODE    = 5,

    DOT11_MAX_MODE

} Dot11Mode;

typedef struct
{
char  MinClass;
char  MaxClass;
char  NumChan;
char  TxPower;
unsigned short Freq;
char  Channel[MAX_CHAN_NUM];
}RegDomainChanPerClass_t;

typedef struct
{
char                     CountryStr[3];
RegDomainChanPerClass_t  DomainReg[MAX_CLASS_NUM];
}RegDomainInfo_t;


RegDomainInfo_t RegDomainTbl[4] = {
                                  {{"US"}, /* Country*/
                                  {{1,1,4,30,5000,{36,40,44,48,0,0,0,0,0,0,0,0,0,0,0}}, /* min class, max class, num of channel,to power, base freq, channel list*/
                                  {2,2,4,23,5000,{52,56,60,64,0,0,0,0,0,0,0,0,0,0,0}},
                                  {3,3,4,29,5000,{149,153,157,161,0,0,0,0,0,0,0,0,0,0,0}},
                                  {4,4,11,23,5000,{100,104,108,112,116,120,124,128,132,136,140,0,0,0,0}},
                                  {5,5,5,30,5000,{149,153,157,161,165,0,0,0,0,0,0,0,0,0,0}},
                                  {10,10,2,20,4850,{20,25,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {11,11,2,33,4850,{20,25,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {12,12,11,30,2407,{1,2,3,4,5,6,7,8,9,10,11,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}}}},
                                  {{"JP"},
                                  {{1,1,4,23,5000,{34,38,42,46,0,0,0,0,0,0,0,0,0,0,0}},
                                  {2,6,3,23,5000,{16,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},/* don't forget to add channel 8,12 for 11N*/
                                  {7,11,4,23,4000,{184,188,192,196,0,0,0,0,0,0,0,0,0,0,0}},
                                  {30,30,13,24,2407,{1,2,3,4,5,6,7,8,9,10,11,12,13,0,0}},
                                  {31,31,1,24,2414,{14,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {32,32,4,23,5000,{52,56,60,64,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}}}},
                                  {{"RST"},
                                  {{1,1,4,23,5000,{36,40,44,46,0,0,0,0,0,0,0,0,0,0,0}},
                                  {2,2,4,23,5000,{52,56,60,64,0,0,0,0,0,0,0,0,0,0,0}},
                                  {3,3,11,30,5000,{100,104,108,112,116,120,124,128,132,136,140,0,0,0,0}},
                                  {4,4,13,20,2407,{1,2,3,4,5,6,7,8,9,10,11,12,13,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}}}},
                                  {{""},
                                  {{100,100,11,13,2407,{1,2,3,4,5,6,7,8,9,10,11,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
                                  {0,0,0,0,0,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}}}}
                                  };


/********************************************************************************/
/*		Internal functions prototypes.					*/
/********************************************************************************/

static int  regulatory_FillChanByCountry(TApChanData  *pChanInfo, char *channelString,int country,int numOfchan,int BaseFreq,int MaxTxPower);
static void regulatory_build_mode_G_hw_capability(RegDomainStruct_t *pRegHandle,TApChanData  *pChanInfo,int NumOfChan,int IfaceIdx);
static void regulatory_build_mode_A_hw_capability(RegDomainStruct_t *pRegHandle,TApChanData  *pChanInfo,int NumOfChan,int IfaceIdx);
static void regulatory_build_mode_B_hw_capability(RegDomainStruct_t *pRegHandle,TApChanData  *pChanInfo,int NumOfChan,int IfaceIdx);

/************************************************************************
 *                        regulatory_create				*
 ************************************************************************
DESCRIPTION: create reg domain handle
INPUT:
************************************************************************/
RegDomainStruct_t *regulatory_create(void)
{
 RegDomainStruct_t *pRegDomain;

  pRegDomain = os_zalloc(sizeof(RegDomainStruct_t));
   if (pRegDomain == NULL )
   {
     wpa_printf(MSG_ERROR, "%s: allocation failed", __func__);
     return NULL;
   }

    pRegDomain->modes = os_zalloc( NUM_HOSTAPD_MODES * sizeof(struct hostapd_hw_modes));
    if (pRegDomain->modes == NULL)
    {
        free(pRegDomain);
        wpa_printf(MSG_ERROR, "%s: allocation failed", __func__);
        return NULL;

    }
  return pRegDomain;
}

/************************************************************************
 *			regulatory_build_hw_capability			*
 ************************************************************************
DESCRIPTION: builds regulatory domain table
INPUT:      pChanStruct - pointer to channel info structure
************************************************************************/
void regulatory_build_hw_capability(RegDomainStruct_t *pRegHandle ,TApChanHwInfo *pChanStruct,char current_channel,hostapd_hw_mode hostapd_mode)
{
 int country;
 unsigned char MaxTxPower = pChanStruct->MaxtxPower/DBM_TO_TX_POWER_FACTOR;
 int index;
 TApChanData  *pChanInfo;

 if (pChanStruct->mode == AP_DOT11_DUAL_MODE)
   pRegHandle->NumOfModes = 2;
 else
   pRegHandle->NumOfModes = 1;

 if (!strncmp(pChanStruct->cCountry,"US",2))
     country  = REG_USA_INDEX;
 else
 if (!strncmp(pChanStruct->cCountry,"JP",2))
    country  = REG_JAPAN_INDEX;
 else
  if (!strncmp(pChanStruct->cCountry,"TI",2))
     country  = REG_TI_INDEX;
  else
   if (!strncmp(pChanStruct->cCountry,"",2))
     country  = REG_ALL_INDEX;
  else
    country  = REG_EUROPE_INDEX;

 wpa_printf(MSG_DEBUG, "%s: Country=%c%c indx=%d", __func__, pChanStruct->cCountry[0], pChanStruct->cCountry[1], country );

 switch (pChanStruct->mode)
 {
 case DOT11_A_MODE:
            pChanInfo = os_zalloc(pChanStruct->numOfAChan * sizeof(TApChanData));
            if (pChanInfo == NULL) {
                wpa_printf(MSG_ERROR, "%s: allocation failed", __func__);
                return;
            }
            index = regulatory_FillChanByCountry(pChanInfo,pChanStruct->Chan5str,country,pChanStruct->numOfAChan,DEFAULT_5_FREQ,MaxTxPower);
            regulatory_build_mode_A_hw_capability(pRegHandle,pChanInfo,index,0);
            free(pChanInfo);
      break;

 case DOT11_B_MODE:
            pChanInfo = os_zalloc(pChanStruct->numOfBChan * sizeof(TApChanData));
            if (pChanInfo == NULL) {
                wpa_printf(MSG_ERROR, "%s: allocation failed", __func__);
                return;
            }
            index = regulatory_FillChanByCountry(pChanInfo,pChanStruct->Chan24str,country,pChanStruct->numOfBChan,DEFAULT_24_FREQ,MaxTxPower);
            regulatory_build_mode_B_hw_capability(pRegHandle,pChanInfo,index,0);
            free(pChanInfo);
      break;

 case DOT11_G_MODE:
           pChanInfo = os_zalloc(pChanStruct->numOfGChan * sizeof(TApChanData));
           if (pChanInfo == NULL) {
               wpa_printf(MSG_ERROR, "%s: allocation failed", __func__);
               return;
           }
           index = regulatory_FillChanByCountry(pChanInfo,pChanStruct->Chan24str,country,pChanStruct->numOfGChan,DEFAULT_24_FREQ,MaxTxPower);
           if (hostapd_mode == HOSTAPD_MODE_IEEE80211B)
             regulatory_build_mode_B_hw_capability(pRegHandle,pChanInfo,index,0); 
           else
           if (current_channel == 14)/*the rates on channel 14 is B rates only*/
           {
             regulatory_build_mode_B_hw_capability(pRegHandle,pChanInfo,index,0);
             pRegHandle->modes[0].mode = HOSTAPD_MODE_IEEE80211G;
           }
           else
             regulatory_build_mode_G_hw_capability(pRegHandle,pChanInfo,index,0);

           free(pChanInfo);
         break;

 case DOT11_DUAL_MODE:
          pChanInfo = os_zalloc(pChanStruct->numOfGChan * sizeof(TApChanData));
          if (pChanInfo == NULL) {
               wpa_printf(MSG_ERROR, "%s: allocation failed", __func__);
               return;
          }
          index = regulatory_FillChanByCountry(pChanInfo,pChanStruct->Chan24str,country,pChanStruct->numOfGChan,DEFAULT_24_FREQ,MaxTxPower);
           if (current_channel == 14)/*the rates on channel 14 is B rates only*/
             regulatory_build_mode_B_hw_capability(pRegHandle,pChanInfo,index,0);
           else
             regulatory_build_mode_G_hw_capability(pRegHandle,pChanInfo,index,0);

          free(pChanInfo);

          pChanInfo = os_zalloc(pChanStruct->numOfAChan * sizeof(TApChanData));
          if (pChanInfo == NULL) {
              wpa_printf(MSG_ERROR, "%s: allocation failed", __func__);
              return;
          }
          index = regulatory_FillChanByCountry(pChanInfo,pChanStruct->Chan5str,country,pChanStruct->numOfAChan,DEFAULT_5_FREQ,MaxTxPower);
          regulatory_build_mode_A_hw_capability(pRegHandle,pChanInfo,index,1);
          free(pChanInfo);

      break;

 default:
     wpa_printf(MSG_ERROR, "%s: illegal Dot11 mode ", __func__);
 }
}


/************************************************************************
 *			regulatory_FillChanByCountry			*
 ************************************************************************
DESCRIPTION: finds and returns channel index by country code
INPUT:      pointer to channel table
RETURN:     channel index
************************************************************************/
static int regulatory_FillChanByCountry(TApChanData  *pChanInfo, char *channelString,int country,int numOfchan,int BaseFreq,int MaxTxPower)
{
int classId,chan;
int index=0;
int i,found;


  for (i=0; i<numOfchan;i++ )
  {
   found = 0;
     if (country  == REG_TI_INDEX)
     {
      pChanInfo[index].chan = channelString[i];
      pChanInfo[index].freq = BaseFreq + 5 * pChanInfo[index].chan;
      pChanInfo[index].max_tx_power = MaxTxPower;
      index++;
     }
     else
     {
       for (classId = 0;(classId < MAX_CLASS_NUM && !found);classId++)
       {
        for (chan = 0;chan<MAX_CHAN_NUM;chan++)
        {
          if (RegDomainTbl[country].DomainReg[classId].Channel[chan] == channelString[i])
         {
          pChanInfo[index].chan = channelString[i];
          pChanInfo[index].freq = RegDomainTbl[country].DomainReg[classId].Freq + 5 * pChanInfo[index].chan;
          pChanInfo[index].max_tx_power = RegDomainTbl[country].DomainReg[classId].TxPower;
          index++;
          found = 1;
         }
        }
       }
     }
  }
  return index;
}

/************************************************************************
 *		regulatory_build_mode_A_hw_capability			*
 ************************************************************************
DESCRIPTION: build mode A hw capability
INPUT:      support channel list
RETURN:
************************************************************************/
static void regulatory_build_mode_A_hw_capability(RegDomainStruct_t *pRegHandle,TApChanData *pChanInfo,int NumOfChan,int IfaceIdx )
{
int NumOfARate = sizeof(RateATbl)/ sizeof(RateATbl[0]);
int i;

  pRegHandle->modes[IfaceIdx].mode = HOSTAPD_MODE_IEEE80211A;
  pRegHandle->modes[IfaceIdx].num_channels = NumOfChan;
  pRegHandle->modes[IfaceIdx].num_rates = NumOfARate;
  pRegHandle->modes[IfaceIdx].channels = os_zalloc(sizeof(struct hostapd_channel_data) * (pRegHandle->modes[IfaceIdx].num_channels)) ;
  pRegHandle->modes[IfaceIdx].rates = os_zalloc(sizeof(struct hostapd_rate_data) * (pRegHandle->modes[IfaceIdx].num_rates));
      if (pRegHandle->modes[IfaceIdx].channels == NULL || pRegHandle->modes[IfaceIdx].rates == NULL) {
          wpa_printf(MSG_ERROR, "%s: allocation failed ", __func__);
          hostapd_free_hw_features(pRegHandle->modes, pRegHandle->NumOfModes);
	      return ;
      }

   for (i=0;i<NumOfChan;i++)
   {
    pRegHandle->modes[IfaceIdx].channels[i].chan = pChanInfo[i].chan;
    pRegHandle->modes[IfaceIdx].channels[i].freq = pChanInfo[i].freq ;
    pRegHandle->modes[IfaceIdx].channels[i].max_tx_power = pChanInfo[i].max_tx_power;
    pRegHandle->modes[IfaceIdx].channels[i].flag = 0;
   }

/* TBD A mode Rates */
    for (i=0;i<NumOfARate;i++)
    {
     pRegHandle->modes[IfaceIdx].rates[i].rate = RateATbl[i];
     pRegHandle->modes[IfaceIdx].rates[i].flags = HOSTAPD_RATE_BASIC | HOSTAPD_RATE_SUPPORTED |HOSTAPD_RATE_MANDATORY;
    }
}

/************************************************************************
 *		regulatory_build_mode_G_hw_capability			*
 ************************************************************************
DESCRIPTION: build mode A hw capability
INPUT:      support channel list
RETURN:
************************************************************************/
static void regulatory_build_mode_G_hw_capability(RegDomainStruct_t *pRegHandle,TApChanData  *pChanInfo,int NumOfChan,int IfaceIdx)
{
 int NumOfGRate = sizeof(RateGTbl)/ sizeof(RateGTbl[0]);
 int i;

  pRegHandle->modes[IfaceIdx].mode = HOSTAPD_MODE_IEEE80211G;
  pRegHandle->modes[IfaceIdx].num_channels = NumOfChan;
  pRegHandle->modes[IfaceIdx].num_rates = NumOfGRate;
  pRegHandle->modes[IfaceIdx].channels = os_zalloc(sizeof(struct hostapd_channel_data) * (pRegHandle->modes[IfaceIdx].num_channels)) ;
  pRegHandle->modes[IfaceIdx].rates = os_zalloc(sizeof(struct hostapd_rate_data) * (pRegHandle->modes[IfaceIdx].num_rates));
  if (pRegHandle->modes[IfaceIdx].channels == NULL || pRegHandle->modes[IfaceIdx].rates == NULL) {
     wpa_printf(MSG_ERROR, "%s: allocation failed ", __func__);
	 hostapd_free_hw_features(pRegHandle->modes, pRegHandle->NumOfModes);
	 return ;
  }

  for (i=0;i<NumOfChan;i++)
   {
    pRegHandle->modes[IfaceIdx].channels[i].chan = pChanInfo[i].chan;
    pRegHandle->modes[IfaceIdx].channels[i].freq = pChanInfo[i].freq ;
    pRegHandle->modes[IfaceIdx].channels[i].max_tx_power = pChanInfo[i].max_tx_power;
    pRegHandle->modes[IfaceIdx].channels[i].flag = 0;
   }

  for (i=0;i<NumOfGRate;i++)
  {
    pRegHandle->modes[IfaceIdx].rates[i].rate = RateGTbl[i];
    pRegHandle->modes[IfaceIdx].rates[i].flags = HOSTAPD_RATE_BASIC | HOSTAPD_RATE_SUPPORTED | HOSTAPD_RATE_CCK | HOSTAPD_RATE_MANDATORY;
  }
}

/************************************************************************
 *		regulatory_build_mode_B_hw_capability			*
 ************************************************************************
DESCRIPTION: build mode B hw capability
INPUT:      support channel list
RETURN:
************************************************************************/
static void regulatory_build_mode_B_hw_capability(RegDomainStruct_t *pRegHandle,TApChanData  *pChanInfo,int NumOfChan,int IfaceIdx)
{
 int NumOfBRate = sizeof(RateBTbl)/ sizeof(RateBTbl[0]);
 int i;

  pRegHandle->modes[IfaceIdx].mode = HOSTAPD_MODE_IEEE80211B;
  pRegHandle->modes[IfaceIdx].num_channels = NumOfChan;
  pRegHandle->modes[IfaceIdx].num_rates = NumOfBRate;
  pRegHandle->modes[IfaceIdx].channels = os_zalloc(sizeof(struct hostapd_channel_data) * (pRegHandle->modes[IfaceIdx].num_channels)) ;
  pRegHandle->modes[IfaceIdx].rates = os_zalloc(sizeof(struct hostapd_rate_data) * (pRegHandle->modes[IfaceIdx].num_rates));
  if (pRegHandle->modes[IfaceIdx].channels == NULL || pRegHandle->modes[IfaceIdx].rates == NULL) {
     wpa_printf(MSG_ERROR, "%s: allocation failed ", __func__);
	 hostapd_free_hw_features(pRegHandle->modes, pRegHandle->NumOfModes);
	 return ;
  }

  for (i=0;i<NumOfChan;i++)
   {
    pRegHandle->modes[IfaceIdx].channels[i].chan = pChanInfo[i].chan;
    pRegHandle->modes[IfaceIdx].channels[i].freq = pChanInfo[i].freq ;
    pRegHandle->modes[IfaceIdx].channels[i].max_tx_power = pChanInfo[i].max_tx_power;
    pRegHandle->modes[IfaceIdx].channels[i].flag = 0;
   }

  for (i=0;i<NumOfBRate;i++)
  {
    pRegHandle->modes[IfaceIdx].rates[i].rate = RateBTbl[i];
    pRegHandle->modes[IfaceIdx].rates[i].flags = HOSTAPD_RATE_BASIC | HOSTAPD_RATE_SUPPORTED | HOSTAPD_RATE_CCK | HOSTAPD_RATE_MANDATORY;
  }
}



void regulatory_destroy (RegDomainStruct_t *pRegHandle)
{
 int i;

 if (pRegHandle)
 {
	 free(pRegHandle);
 }

}

