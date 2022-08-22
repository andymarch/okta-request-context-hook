'use strict';
const axios = require('axios');

module.exports.hello = async (event) => {
    var structure = {}
    var commands = 'commands'
    structure[commands] = []
    
    var payload = JSON.parse(event.body)
  
    var challenge = {}
    const response = await axios.get('https://'+process.env.ORG+'/api/v1/logs',
    {
      params:{
        filter: 'eventType eq "policy.evaluate_sign_on" and actor.id eq "'+payload.data.identity.claims.sub+'"',
        limit:1,
        sortOrder: 'DESCENDING'
      },
      headers:{'Authorization':'SSWS '+process.env.ORG_TOKEN}
    })
    challenge.client = {
        browser: response.data[0].client.userAgent.browser,
        os: response.data[0].client.userAgent.os,
        location: {
          ip: response.data[0].client.ipAddress,
          country: response.data[0].client.geographicalContext.country,
          geolocation: response.data[0].client.geographicalContext.geolocation
        }
      }
    challenge.threatSuspected = response.data[0].debugContext.debugData.threatSuspected
    challenge.risk = response.data[0].debugContext.debugData.risk
    challenge.behaviour = response.data[0].debugContext.debugData.behaviors
  
    //challenge.ip = payload.data.context.request.ipAddress
    var command = {
        'type': 'com.okta.identity.patch',
        'value': [
            {
              'op': 'add',
              'path': '/claims/context',
              'value': challenge
            }
        ]
    }
    structure[commands].push(command)
    console.log(JSON.stringify(structure))
    return {
      statusCode: 200,
      body: JSON.stringify(structure)
    }
};
