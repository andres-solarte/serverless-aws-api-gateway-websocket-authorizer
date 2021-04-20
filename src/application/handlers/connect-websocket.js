const handler = async (event, context) => {
  console.log('Connected Websocket', JSON.stringify(event))

  return {
    statusCode: 200,
    body: JSON.stringify({ msg: 'OK'})
  }
}

module.exports = { handler }
