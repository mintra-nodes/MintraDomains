const axios = require('axios');

require('dotenv').config();

const API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;

const ZONE_IDS = process.env.ZONE_IDS.split(',');

const getZoneIdByDomain = (domain) => {

  const domains = process.env.DOMAINS.split(',');

  const index = domains.indexOf(domain);

  console.log('Domains:', domains, 'Looking for:', domain, 'Index:', index);

  return index !== -1 ? ZONE_IDS[index] : null;

};

async function createSubdomain(subdomain, domain, ipv4, port) {
  console.log('=== Debug Info ===');
  console.log('Subdomain:', subdomain);
  console.log('Domain:', domain); 
  console.log('IPv4:', ipv4);
  console.log('Port:', port);
  console.log('API Token:', API_TOKEN ? 'Set' : 'Undefined');

  const zoneId = getZoneIdByDomain(domain);

  if (!zoneId) return { success: false, message: `No Zone ID for ${domain}` };

  try {

    const aResponse = await axios.post(

      `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`,

      { type: 'A', name: `${subdomain}.${domain}`, content: ipv4, ttl: 1, proxied: false },

      { headers: { 'Authorization': `Bearer ${API_TOKEN}`, 'Content-Type': 'application/json' } }

    );

    const srvResponse = await axios.post(

      `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`,

      { 

        type: 'SRV',

        name: `_minecraft._tcp.${subdomain}.${domain}`,

        data: {

          service: '_minecraft',

          proto: '_tcp',

          name: `${subdomain}.${domain}`,

          priority: 1,

          weight: 1,

          port: port,

          target: `${subdomain}.${domain}`

        },

        ttl: 1

      },

      { headers: { 'Authorization': `Bearer ${API_TOKEN}`, 'Content-Type': 'application/json' } }

    );

    return { success: true, result: { a: aResponse.data, srv: srvResponse.data } };

  } catch (error) {

    console.error('Cloudflare Error:', error.response ? error.response.data : error.message);

    return { success: false, message: error.response ? JSON.stringify(error.response.data.errors) : error.message };

  }

}

async function deleteSubdomain(subdomain, domain) {

  const zoneId = getZoneIdByDomain(domain);

  if (!zoneId) return { success: false, message: `No Zone ID for ${domain}` };

  

  try {

    // Get all DNS records

    const listResponse = await axios.get(

      `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`,

      { 

        headers: { 'Authorization': `Bearer ${API_TOKEN}`, 'Content-Type': 'application/json' }

      }

    );

    if (!listResponse.data.success) {

      return { success: false, message: 'Failed to fetch DNS records' };

    }

    // Filter records for both A and SRV records

    const records = listResponse.data.result.filter(record => 

      (record.name === `${subdomain}.${domain}` && record.type === 'A') || 

      (record.name === `_minecraft._tcp.${subdomain}.${domain}` && record.type === 'SRV')

    );

    if (records.length === 0) {

      return { success: true, message: 'No DNS records found' };

    }

    // Delete all matching records

    const deleteResults = await Promise.all(

      records.map(record =>

        axios.delete(

          `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${record.id}`,

          { headers: { 'Authorization': `Bearer ${API_TOKEN}`, 'Content-Type': 'application/json' } }

        )

      )

    );

    const allSuccessful = deleteResults.every(result => result.data.success);

    return { 

      success: allSuccessful, 

      message: allSuccessful ? 'All DNS records deleted successfully' : 'Some records failed to delete'

    };

  } catch (error) {

    console.error('Cloudflare Error:', error.response ? error.response.data : error.message);

    return { 

      success: false, 

      message: error.response ? JSON.stringify(error.response.data.errors) : error.message 

    };

  }

}

module.exports = { createSubdomain, deleteSubdomain };