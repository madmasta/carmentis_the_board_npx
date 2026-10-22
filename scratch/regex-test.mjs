const body = "        (new TheBoard\\Http\\AuthController())->loginForm();";
console.log('runtime body:', body);
console.log('len', body.length);
console.log('index of AuthController:', body.indexOf('AuthController'));
console.log('after:', JSON.stringify(body.slice(body.indexOf('AuthController'))));
console.log('match \\w+\\):', /\w+\)/.exec(body)?.[0]);
console.log('match Http..Controller:', /Http\\(\w+)\)/.exec(body)?.[0]);
console.log('match Http..Controller noescape:', /Http.(.*?)\)/.exec(body)?.[0]);
