# NodeB2f

This package is used for Node.js webservers that use Blue2Factor

### To install with npm
```
npm install blue2factor
```

##### Or on GitHub at [https://github.com/bk89686/NodeB2f](https://github.com/bk89686/NodeB2f)

### To use :

```
const b2f = require("./blue2factor");

const companyId = "COMPANY_ID from https://secure.blue2factor.com"
const loginUrl = "LOGIN_URL that was entered at https://secure.blue2factor.com"

...
app.all('/', async (req, res) => {
	if (!(await b2f.authenticateRequestExpress(req, companyId, loginUrl, getPvtKey()))){
		return b2f.getRedirect(res);
	}
	res = b2f.setB2fCookie(res);
	//do what you normally do
});

function getPvtKey(){
	//your own function to get the private key that corresponds to the public key that
	//you uploaded to https://secure.blue2factor.com
}
```


for questions, please contact us at (607) 238-3522 or help@blue2factor.com