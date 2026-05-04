Rebol [
	Name:    postgres
	Type:    module
	Options: [delay]
	Version: 0.1.1
	Date:    13-Mar-2025
	File:    %postgres.reb
	Title:   "PostgresSQL protocol scheme"
	Author:  [@Oldes @Rebolek]
	Rights:  "Copyright (C) 2025 Oldes. All rights reserved."
	License: MIT
	Home:    https://github.com/Oldes/Rebol-Postgres
	History: [
		0.1.0 28-Feb-2025 @Oldes "Initial version"
	]
	Notes: {
		* https://www.postgresql.org/docs/current/protocol-flow.html
		* https://www.postgresql.org/docs/current/protocol-message-formats.html

		Postgres server may be started using Docker with command:
		```
		docker run -d --name postgres -p 5432:5432 -e POSTGRES_PASSWORD=password postgres
		```
	}
	Usage: [
		pg: open postgres://postgress:password@localhost
		probe write pg "SELECT version();"
	]
]

system/options/log/postgres: 2

scram: func [
	"SCRAM Authentication Exchange"
	state [object!] "Populated context with input/output values"
	/local hash ;; not needed in the state
][
	with state [
		SaltedPassword: make binary! 32
		hash: join salt #{00000001}
		hash: SaltedPassword: checksum/with hash :method :password
		loop iterations - 1 [
			SaltedPassword: SaltedPassword xor (hash: checksum/with hash :method :password)
		]
		ClientKey: checksum/with "Client Key" :method :SaltedPassword
		ServerKey: checksum/with "Server Key" :method :SaltedPassword
		StoredKey: checksum :ClientKey :method

		AuthMessage: rejoin [
			client-first-message-bare #","
			server-first-message #","
			client-final-message-without-proof
		]
		ClientSignature: checksum/with :AuthMessage :method :StoredKey
		ServerSignature: checksum/with :AuthMessage :method :ServerKey
		ClientProof: ClientSignature xor ClientKey
	]
]

authenticate: funct [ctx] [
	; Select a supported mechanism from server-offered preferences (handled in AuthenticationSASL).
	nonce: make binary! 24
	binary/write nonce [random-bytes 24]
	ctx/sasl/client-first-message-bare: ajoin [
		"n=" ctx/sasl/user ",r=" enbase nonce 64
	]
	msg: join ctx/sasl/gs2-header ctx/sasl/client-first-message-bare
	mech: ajoin [any [ctx/sasl/mechanism "SCRAM-SHA-256"] null]
	response: clear #{}
	binary/write response [
		BYTES     :mech
		UI32BYTES :msg
	]
	response
]

md5-password: funct [
	"Compute PostgreSQL MD5 auth response"
	user     [string!]
	password [string!]
	salt     [binary!]
][
	inner: checksum ajoin [password user] 'md5
	inner-hex: lowercase enbase inner 16
	data: to binary! inner-hex
	append data salt
	outer: checksum data 'md5
	rejoin ["md5" lowercase enbase outer 16]
]

make-startup-message: funct [
	;- This packet is special and so is not used in a output que!
	user     [string!]
	database [string!]
	options  [map! none!]
] [
	; Send StartupMessage
	app: any [all [options select options 'application_name] none]
	startup-message: rejoin [
		#{00000000} ; Length placeholder
		#{00030000} ; Protocol version (3.0)
		"user^@"     user     null ; Default username
		"database^@" database null ; Default database
		either app [rejoin ["application_name^@" app null]][copy ""]
		null ; Terminator
	]

	; Set correct length
	len: length? startup-message
	binary/write startup-message [UI32 :len]
	startup-message
]

que-packet: function[
	;- Forms a new packet and appends it to an output buffer.
	ctx type msg
][
	out: tail ctx/out-buffer
	; Avoid leaking auth secrets in logs, and allow log verbosity control.
	trace?: all [ctx/options select ctx/options 'trace?]
	either type = #"p" [
		sys/log/debug 'POSTGRES ["Client-> type:" as-blue type as-yellow "<auth redacted>"]
	][
		either trace? [
			sys/log/debug 'POSTGRES ["Client-> type:" as-blue type as-yellow mold msg]
		][
			sys/log/debug 'POSTGRES ["Client-> type:" as-blue type "len:" length? msg]
		]
	]
	len: 4 + length? msg
	binary/write out [
		UI8 :type
		UI32 :len
		BYTES :msg
	]
]

make-cancel-request: func [
	"Build CancelRequest packet (len=16, code=80877102)"
	pid [integer!]
	key [integer!]
][
	pkt: make binary! 16
	binary/write pkt [
		UI32 16
		UI32 80877102
		UI32 pid
		UI32 key
	]
	pkt
]

make-cstring: func [
	"Encode a Rebol string as a C-string (null-terminated)"
	s [any-type!]
][
	to binary! join form any [s ""] null
]

make-parse-message: func [
	"Build Parse message body"
	stmt-name [any-type!]
	query [string!]
	param-oids [block! none!]
	/local oids msg count cs-stmt cs-query
][
	oids: any [param-oids copy []]
	msg: clear make binary! (64 + length? query)
	cs-stmt: make-cstring stmt-name
	cs-query: make-cstring query
	append msg cs-stmt
	append msg cs-query
	count: length? oids
	binary/write tail msg [UI16 :count]
	foreach oid oids [
		binary/write tail msg [UI32 to integer! oid]
	]
	msg
]

encode-param-text: func [
	"Encode a single parameter value to text bytes (or none for NULL)"
	v [any-type!]
][
	case [
		none? v [none]
		logic? v [either v ["t"]["f"]]
		'else [form v]
	]
]

make-bind-message: func [
	"Build Bind message body (text params, result format = text)"
	portal-name [any-type!]
	stmt-name [any-type!]
	params [block!]
	/local msg p enc cs-portal cs-stmt count
][
	msg: clear make binary! 128
	cs-portal: make-cstring portal-name
	cs-stmt: make-cstring stmt-name
	append msg cs-portal
	append msg cs-stmt
	count: length? params
	binary/write tail msg [
		UI16  0                ; parameter format codes (0 = all text)
		UI16  :count           ; number of parameter values
	]
	foreach p params [
		enc: encode-param-text p
		either none? enc [
			binary/write tail msg [SI32 -1]
		][
			enc: to binary! enc
			binary/write tail msg [SI32 length? enc BYTES :enc]
		]
	]
	binary/write tail msg [
		UI16 0 ; result-column format codes (0 = all text)
	]
	msg
]

make-describe-message: func [
	"Build Describe message body"
	kind [char!]
	name [any-type!]
	/local msg cs k
][
	msg: clear make binary! 32
	cs: make-cstring name
	k: to integer! kind
	binary/write msg [UI8 :k]
	append msg cs
	head msg
]

make-execute-message: func [
	"Build Execute message body"
	portal-name [any-type!]
	max-rows [integer!]
	/local msg cs mr
][
	msg: clear make binary! 32
	cs: make-cstring portal-name
	append msg cs
	mr: max-rows
	binary/write tail msg [UI32 :mr]
	msg
]

make-close-message: func [
	"Build Close message body (S=statement, P=portal)"
	kind [char!]
	name [any-type!]
	/local msg cs k
][
	msg: clear make binary! 32
	cs: make-cstring name
	k: to integer! kind
	binary/write msg [UI8 :k]
	append msg cs
	head msg
]

error-fields: #[
	;- https://www.postgresql.org/docs/current/protocol-error-fields.html
	0#53 localized-severity   ;= S - the field contents are ERROR, FATAL, or PANIC (in an error message), or WARNING, NOTICE, DEBUG, INFO, or LOG (in a notice message), or a localized translation of one of these. Always present.
	0#56 severity             ;= V - the field contents are ERROR, FATAL, or PANIC (in an error message), or WARNING, NOTICE, DEBUG, INFO, or LOG (in a notice message). This is identical to the S field except that the contents are never localized. This is present only in messages generated by PostgreSQL versions 9.6 and later.
	0#43 sql-state            ;= C - the SQLSTATE code for the error (see Appendix A). Not localizable. Always present.
	0#4D message              ;= M - the primary human-readable error message. This should be accurate but terse (typically one line). Always present.
	0#44 detail               ;= D - an optional secondary error message carrying more detail about the problem. Might run to multiple lines.
	0#48 hint                 ;= H - an optional suggestion what to do about the problem. This is intended to differ from Detail in that it offers advice (potentially inappropriate) rather than hard facts. Might run to multiple lines.
	0#50 position             ;= P - the field value is a decimal ASCII integer, indicating an error cursor position as an index into the original query string. The first character has index 1, and positions are measured in characters not bytes.
	0#70 internal-position    ;= p - this is defined the same as the P field, but it is used when the cursor position refers to an internally generated command rather than the one submitted by the client. The q field will always appear when this field appears.
	0#71 internal-query       ;= q - the text of a failed internally-generated command. This could be, for example, an SQL query issued by a PL/pgSQL function.
	0#57 where                ;= W - an indication of the context in which the error occurred. Presently this includes a call stack traceback of active procedural language functions and internally-generated queries. The trace is one entry per line, most recent first.
	0#73 schema-name          ;= s - if the error was associated with a specific database object, the name of the schema containing that object, if any.
	0#74 table-name           ;= t - if the error was associated with a specific table, the name of the table. (Refer to the schema name field for the name of the table's schema.)
	0#63 column-name          ;= c - if the error was associated with a specific table column, the name of the column. (Refer to the schema and table name fields to identify the table.)
	0#64 datatype-name        ;= d - if the error was associated with a specific data type, the name of the data type. (Refer to the schema name field for the name of the data type's schema.)
	0#6E constraint-name      ;= n - if the error was associated with a specific constraint, the name of the constraint. Refer to fields listed above for the associated table or domain. (For this purpose, indexes are treated as constraints, even if they weren't created with constraint syntax.)
	0#46 file                 ;= F - the file name of the source-code location where the error was reported.
	0#4C line                 ;= L - the line number of the source-code location where the error was reported.
	0#52 routine              ;= R - the name of the source-code routine reporting the error.
]

process-responses: function[
	;- Process all incoming data.
	ctx [object!]
][
	;pg: ctx/conn/parent
	;; Move data from the TCP buffer to the input buffer before processing
	append ctx/inp-buffer take/all ctx/connection/data
	sys/log/debug 'POSTGRES ["Process input length:" length? ctx/inp-buffer]
	bin: binary head ctx/inp-buffer
	while [5 <= length? bin/buffer][
		binary/read bin [
			type: UI8
			len:  UI32
		]
		body-len: len - 4
		body-start: length? bin/buffer
		if body-len > length? bin/buffer [
			break
		]
		type: to char! type
		switch/default/case type [
			#"R" [
				auth-id: binary/read bin 'UI32
				sys/log/more 'POSTGRES ["Authentication message type:" as-yellow auth-id]
				switch/default auth-id [
					0 [
						;; Specifies that the authentication was successful.
						ctx/authenticated?: true
					]
					3 [
						;; AuthenticationCleartextPassword
						unless all [
							ctx/options
							select ctx/options 'allow-cleartext?
						][
							ctx/error: make map! reduce ['message "Cleartext password auth disabled by client"]
							sys/log/error 'POSTGRES select ctx/error 'message
							break
						]
						que-packet ctx #"p" join ctx/sasl/password null
					]
					5 [
						;; AuthenticationMD5Password
						unless any [
							not ctx/options
							find select ctx/options 'auth 'md5
						][
							ctx/error: make map! reduce ['message "MD5 password auth disabled by client"]
							sys/log/error 'POSTGRES select ctx/error 'message
							break
						]
						salt: binary/read bin 4
						que-packet ctx #"p" join md5-password ctx/sasl/user ctx/sasl/password salt null
					]
					10 [
						;; The message body is a list of SASL authentication mechanisms,
						;; in the server's order of preference. A zero byte is required
						;; as terminator after the last authentication mechanism name.
						tmp: clear ctx/sasl/mechanisms
						until [
							name: binary/read bin 'STRING
							none? unless empty? name [
								append tmp name
							]
						]
						;; Choose a supported mechanism from the offered list.
						case [
							all [
								any [
									not ctx/options
									find select ctx/options 'auth 'scram
								]
								find tmp "SCRAM-SHA-256"
							][
								ctx/sasl/mechanism: "SCRAM-SHA-256"
								sys/log/debug 'POSTGRES ["Using SASL mechanism:" ctx/sasl/mechanism]
								que-packet ctx #"p" authenticate ctx
							]
							'else [
								ctx/error: make map! reduce [
									'message ajoin ["Unsupported SASL mechanisms: " mold tmp]
								]
								sys/log/error 'POSTGRES select ctx/error 'message
								break
							]
						]
					]
					11 [
						;; Complete server response is used in the authentication exchange!
						;; pg/state: 'AuthenticationSASLContinue
						ctx/sasl/server-first-message: data: to string! binary/read bin len - 8
						ctx/sasl/client-final-message-without-proof: ajoin [
							"c=" enbase ctx/sasl/gs2-header 64 ",r="
						]
						parse data [
							"r=" copy tmp: to #"," skip (append ctx/sasl/client-final-message-without-proof tmp)
							"s=" copy tmp: to #"," skip (ctx/sasl/salt: debase tmp 64)
							"i=" copy tmp: to end (ctx/sasl/iterations: to integer! tmp)
						]
						scram ctx/sasl
						;? ctx/sasl
						que-packet ctx #"p" ajoin [
							ctx/sasl/client-final-message-without-proof
							",p=" enbase ctx/sasl/ClientProof 64
						]
					]
					12 [
						;; pg/state: 'AuthenticationSASLFinal
						tmp: to string! binary/read bin len - 8
						unless all [
							parse tmp ["v=" tmp: to end]
							ctx/sasl/ServerSignature == debase tmp 64
						][
							sys/log/error 'POSTGRES "Final authentication failed!"
						]
					]
				][
					ctx/error: ajoin ["Unknown authentication message of type " auth-id]
					sys/log/error 'POSTGRES ["Unknown authentication message of type" ctx/error]
					break
				]
			]
			#"T" [
				;; Identifies the message as a row description.
				cols: binary/read bin 'UI16
				loop cols [
					append/only ctx/RowDescription tmp: binary/read bin [
						STRING ;; The field name.
						SI32   ;; If the field can be identified as a column of a specific table, the object ID of the table; otherwise zero.
						SI16   ;; If the field can be identified as a column of a specific table, the attribute number of the column; otherwise zero.
						SI32   ;; The object ID of the field's data type.
						SI16   ;; The data type size (see pg_type.typlen). Note that negative values denote variable-width types.
						SI32   ;; The type modifier (see pg_attribute.atttypmod). The meaning of the modifier is type-specific.
						SI16   ;; The format code being used for the field. Currently will be zero (text) or one (binary). In a RowDescription returned from the statement variant of Describe, the format code is not yet known and will always be zero.
					]
					sys/log/more 'POSTGRES ["Column description:^[[m" tmp]
				]
			]
			#"D" [
				;; Identifies the message as a data row.
				cols: binary/read bin 'UI16
				row: clear []
				loop cols [
					len: binary/read bin 'SI32
					tmp: case [
						len == -1 [ none ]
						len ==  0 [ "" ]
						'else	  [ to string! binary/read bin len ] ;@@ should be converted acording the type from the description!
					]
					sys/log/more 'POSTGRES ["Column data:^[[m" ellipsize copy/part tmp 80 75]
					append row tmp
				]
				either all [
					ctx/inflight
					select ctx/inflight 'stream?
					select ctx/inflight 'on-row
				][
					ctx/inflight/row-index: ctx/inflight/row-index + 1
					shaped: shape-row ctx row
					invoke-callback ctx/inflight/on-row shaped
				][
					append/only ctx/data row
				]
			]
			#"C" [
				;; Identifies the message as a command-completed response.
				ctx/CommandComplete: tmp: to string! binary/read bin len - 4
				sys/log/more 'POSTGRES ["Command completed:^[[m" tmp]
			]
			#"1" [
				;; ParseComplete (extended query protocol)
				sys/log/more 'POSTGRES "ParseComplete"
			]
			#"2" [
				;; BindComplete (extended query protocol)
				sys/log/more 'POSTGRES "BindComplete"
			]
			#"3" [
				;; CloseComplete (extended query protocol)
				sys/log/more 'POSTGRES "CloseComplete"
			]
			#"n" [
				;; NoData (e.g. Describe returned no rows)
				sys/log/more 'POSTGRES "NoData"
			]
			#"s" [
				;; PortalSuspended (Execute terminated due to row limit)
				ctx/PortalSuspended?: true
				sys/log/more 'POSTGRES "PortalSuspended"
			]
			#"E"
			#"N" [
				err: clear []
				while [0 != field: binary/read bin 'UI8][
					repend err [
						select error-fields field
						binary/read bin 'STRING
					]
				]
				either type == #"E" [
					ctx/error: make map! err
					sys/log/error 'POSTGRES any [select err 'message "Malformed error message"]
				][
					;-- Keep notices so `write` can return them.
					append ctx/notices make map! err
					sys/log/info 'POSTGRES ["NOTICE:" select err 'message]
				]
			]
			#"S" [
				;; Identifies the message as a run-time parameter status report.
				tmp: binary/read bin [STRING STRING]
				sys/log/info 'POSTGRES ["Run-time parameter:" as-yellow form tmp]
				repend ctx/runtime [to word! tmp/1 tmp/2]
			]
			#"K" [
				;; Identifies the message as cancellation key data.
				;; The frontend must save these values if it wishes to be able to issue CancelRequest messages later.
				ctx/CancelKeyData: binary/read bin [UI32 UI32]
				sys/log/more 'POSTGRES ["CancelKeyData:" ctx/CancelKeyData]
			]
			#"A" [
				;; NotificationResponse (LISTEN/NOTIFY)
				pid: binary/read bin 'UI32
				channel: binary/read bin 'STRING
				payload: binary/read bin 'STRING
				evt: make map! reduce [
					'pid pid
					'channel channel
					'payload payload
				]
				sys/log/more 'POSTGRES ["Notification:" channel payload]
				; Invoke catch-all handler first (if any), then channel-specific handlers.
				invoke-callback ctx/notify-any evt
				handlers: select ctx/notify-handlers channel
				if block? handlers [
					foreach h handlers [invoke-callback h evt]
				]
			]
			#"Z" [
				;; Identifies the message type.
				;; ReadyForQuery is sent whenever the backend is ready for a new query cycle.
				ctx/ReadyForQuery: to char! binary/read bin 'UI8
				sys/log/more 'POSTGRES ["ReadyForQuery:" ctx/ReadyForQuery]
			]
		][
			sys/log/error 'POSTGRES ["Unknown message type:" type]
			binary/read bin body-len
		]

		;-- Validate that handler consumed exactly declared message body length.
		consumed: body-start - length? bin/buffer
		case [
			consumed < body-len [
				; Handler did not consume all bytes; skip remainder.
				binary/read bin body-len - consumed
			]
			consumed > body-len [
				; Handler over-consumed (stream is now out-of-sync). Stop and surface error.
				ctx/error: make map! reduce [
					'message ajoin ["Protocol desync (consumed " consumed " bytes, expected " body-len ")"]
				]
				sys/log/error 'POSTGRES select ctx/error 'message
				break
			]
		]
	]
	;; Remove all processed data from the head of the input buffer
	truncate bin/buffer
	;; Return true if the input buffer is empty
	tail? bin/buffer
]

clean-cstring: func [
	"Remove C-string terminator if present"
	s [string!]
	/local p
][
	either p: find s null [copy/part s p][s]
]

parse-query-params: func [
	"Parse URL query string into a map"
	q [any-type!]
	/local m s part k v eq
][
	m: make map! 8
	if any [none? q empty? s: form q] [return m]
	foreach part split s #"&" [
		either eq: find part #"=" [
			k: copy/part part eq
			v: copy next eq
		][
			k: part
			v: "true"
		]
		if all [k not empty? k] [
			put m to word! k v
		]
	]
	m
]

parse-timeout-seconds: func [
	"Parse timeout seconds (integer >= 0); returns none on invalid"
	s [any-type!]
	/local v n
][
	if none? s [return none]
	v: trim form s
	if empty? v [return none]
	n: attempt [to integer! v]
	if any [none? n n < 0] [return none]
	n
]

parse-trace-flag: func [
	"Parse a boolean-ish query flag"
	s [any-type!]
	/local v
][
	v: lowercase trim form any [s ""]
	any [
		v = "1"
		v = "true"
		v = "on"
		v = "yes"
		v = "trace"
	]
]

parse-log-level: func [
	"Parse log level integer (returns none if invalid)"
	s [any-type!]
	/local v n
][
	if none? s [return none]
	v: trim form s
	if empty? v [return none]
	n: attempt [to integer! v]
	if any [none? n n < 0 n > 9] [return none]
	n
]

pg-quote-ident: func [
	"Quote SQL identifier (e.g. channel name) if needed"
	s [string!]
	/local safe out allowed
][
	allowed: charset [
		#"a" - #"z"
		#"A" - #"Z"
		#"0" - #"9"
		#"_"
		#"$"
	]
	safe: parse s [some allowed]
	either safe [
		s
	][
		out: copy s
		replace/all out {"} {""}
		rejoin [{"} out {"}]
	]
]

format-search-path: func [
	"Format search_path list safely (supports $user and comma-separated schema names)"
	raw [any-type!]
	/local items out item trimmed res
][
	items: split trim form any [raw ""] #","
	out: make block! 8
	foreach item items [
		trimmed: trim form item
		if empty? trimmed [continue]
		either trimmed = "$user" [
			append out "$user"
		][
			append out pg-quote-ident trimmed
		]
	]
	if empty? out [return none]
	res: form out/1
	if 1 < length? out [
		foreach item next out [
			append res ", "
			append res form item
		]
	]
	res
]

pg-quote-literal: func [
	"Quote SQL string literal"
	s [string!]
	/local out
][
	out: copy s
	replace/all out {'} {''}
	rejoin [{' out '}]
]

listen: func [
	"LISTEN on a channel and register a handler"
	pg [port!]
	channel [string!]
	handler [any-type!]
	/local ctx handlers
][
	unless open? pg [cause-error 'Access 'not-open pg/spec/ref]
	ctx: pg/extra
	unless ctx/notify-handlers [ctx/notify-handlers: make map! 20]
	handlers: any [select ctx/notify-handlers channel copy []]
	if none? find handlers handler [append/only handlers handler]
	put ctx/notify-handlers channel handlers
	write pg ajoin ["LISTEN " pg-quote-ident channel ";"]
	pg
]

unlisten: func [
	"UNLISTEN a channel (and unregister local handlers)"
	pg [port!]
	channel [string!]
	/local ctx
][
	unless open? pg [cause-error 'Access 'not-open pg/spec/ref]
	ctx: pg/extra
	if all [ctx/notify-handlers select ctx/notify-handlers channel] [
		remove/key ctx/notify-handlers channel
	]
	write pg ajoin ["UNLISTEN " pg-quote-ident channel ";"]
	pg
]

notify: func [
	"Send a NOTIFY"
	pg [port!]
	channel [string!]
	payload [string!]
][
	unless open? pg [cause-error 'Access 'not-open pg/spec/ref]
	write pg ajoin [
		"NOTIFY " pg-quote-ident channel ", " pg-quote-literal payload ";"
	]
	pg
]

cancel: func [
	"Send CancelRequest for currently inflight query (if possible)"
	pg [port!]
	/local ctx key pid cancel-conn pkt host port res
][
	unless port? :pg [cause-error 'Script 'invalid-arg reduce ['cancel pg]]
	unless open? pg [return false]
	ctx: pg/extra
	unless ctx/inflight [return false]
	unless all [ctx/CancelKeyData block? ctx/CancelKeyData 2 <= length? ctx/CancelKeyData] [
		cause-error 'Access 'Protocol make map! reduce ['message "CancelRequest unavailable (missing BackendKeyData)"]
	]
	pid: to integer! ctx/CancelKeyData/1
	key: to integer! ctx/CancelKeyData/2
	host: pg/spec/host
	port: pg/spec/port
	pkt: make-cancel-request pid key
	cancel-conn: make port! [
		scheme: 'tcp
		host: host
		port: port
		ref:  rejoin [tcp:// host #":" port]
	]
	res: try [
		open cancel-conn
		write cancel-conn pkt
		close cancel-conn
		true
	]
	if error? :res [return false]
	true
]

parse-auth-list: func [
	"Parse auth option value into list of allowed methods"
	s [any-type!]
	/local out item val
][
	out: make block! 4
	if any [none? s empty? val: trim form s] [return out]
	foreach item split val #"," [
		item: lowercase trim item
		if not empty? item [append out to word! item]
	]
	out
]

parse-row-mode: func [
	"Parse row option into one of: flat/block/map"
	s [any-type!]
	/local val
][
	val: lowercase trim form any [s ""]
	switch/default val [
		""      ['flat]
		"flat"  ['flat]
		"block" ['block]
		"map"   ['map]
	]['flat]
]

parse-decode-mode: func [
	"Parse decode option into one of: off/basic"
	s [any-type!]
	/local val
][
	val: lowercase trim form any [s ""]
	switch/default val [
		""      ['off]
		"off"   ['off]
		"basic" ['basic]
	]['off]
]

decode-basic-value: func [
	"Convert a text-format field value based on type OID"
	oid [integer!]
	val [any-type!]
	/local tmp
][
	if none? val [return none]
	if not string? val [val: form val]
	val: trim val
	switch/default oid [
		16 [ ; bool
			val: lowercase val
			any [
				val = "t"
				val = "true"
				val = "1"
			]
		]
		20 21 23 [ ; int8/int2/int4
			any [attempt [to integer! val] val]
		]
		700 701 1700 [ ; float4/float8/numeric
			any [attempt [to decimal! val] val]
		]
		1082 [ ; date
			any [attempt [to date! val] val]
		]
	][
		val
	]
]

shape-rows: func [
	"Shape + optionally decode collected rows"
	ctx [object!]
	/local mode decode cols rows-out names row out-row i col oid row-map n
][
	mode: any [all [ctx/options select ctx/options 'row-mode] 'flat]
	decode: any [all [ctx/options select ctx/options 'decode] 'off]
	cols: ctx/RowDescription

	; Build a list of column names (aligned with row values).
	names: collect [
		foreach col cols [keep col/1]
	]

	rows-out: make block! length? ctx/Data
	foreach row ctx/Data [
		out-row: row
		if decode = 'basic [
			out-row: copy row
			i: 0
			foreach v out-row [
				++ i
				col: pick cols i
				oid: any [all [col integer? col/4 col/4] 0]
				change at out-row i decode-basic-value oid v
			]
		]
		switch mode [
			block [
				append/only rows-out out-row
			]
			map [
				row-map: make map! (2 * length? names)
				i: 0
				foreach n names [
					++ i
					put row-map to word! n pick out-row i
				]
				append/only rows-out row-map
			]
			flat [
				; Legacy output: flatten all values into one block.
				append rows-out out-row
			]
		]
	]
	rows-out
]

shape-row: func [
	"Shape + optionally decode a single row"
	ctx [object!]
	row [block!]
	/local mode decode cols names out-row i col oid row-map n
][
	mode: any [all [ctx/options select ctx/options 'row-mode] 'flat]
	decode: any [all [ctx/options select ctx/options 'decode] 'off]
	cols: ctx/RowDescription

	; Build a list of column names (aligned with row values).
	names: collect [
		foreach col cols [keep col/1]
	]

	out-row: row
	if decode = 'basic [
		out-row: copy row
		i: 0
		foreach v out-row [
			++ i
			col: pick cols i
			oid: any [all [col integer? col/4 col/4] 0]
			change at out-row i decode-basic-value oid v
		]
	]

	switch mode [
		block [out-row]
		map [
			row-map: make map! (2 * length? names)
			i: 0
			foreach n names [
				++ i
				put row-map to word! n pick out-row i
			]
			row-map
		]
		flat [
			; For streaming, return the row values (not nested).
			out-row
		]
	]
]

parse-sslmode: func [
	"Parse sslmode option into one of: disable/prefer/require"
	s [any-type!]
	/local val
][
	val: lowercase trim form any [s ""]
	switch/default val [
		""       ['disable]
		"disable" ['disable]
		"prefer"  ['prefer]
		"require" ['require]
	]['disable]
]

make-sslrequest: func [
	"Build SSLRequest packet (len=8, code=80877103)"
][
	req: make binary! 8
	binary/write req [
		UI32 8
		UI32 80877103
	]
	req
]

reset-result-state: func [
	"Reset ctx fields used to accumulate a single request result"
	ctx [object!]
][
	ctx/error: none
	ctx/CommandComplete: none
	ctx/last-error: none
	ctx/last-result: none
	ctx/PortalSuspended?: false
	clear ctx/notices
	clear ctx/Data
	clear ctx/RowDescription
	; runtime is connection-wide; don't clear it per request
]

reset-fetch-state: func [
	"Reset only fields needed between portal FETCH chunks"
	ctx [object!]
][
	ctx/error: none
	ctx/CommandComplete: none
	ctx/PortalSuspended?: false
	clear ctx/Data
	; keep RowDescription, notices, runtime
]

invoke-callback: func [
	"Invoke callback (supports func!, :fn, or 'fn)"
	cb  [any-type!]
	arg [any-type!]
	/local fn
][
	if none? cb [return none]
	fn: case [
		function? :cb [:cb]
		any [word? cb get-word? cb] [
			; `get` retrieves the value without invoking it.
			try [get cb]
		]
		'else [none]
	]
	if function? :fn [
		try [fn :arg]
	]
]

build-result: func [
	"Build a stable result map from current ctx state"
	ctx [object!]
	/local cols rt rows result tag row-count parts
][
	cols: collect [
		foreach col ctx/RowDescription [
			keep compose/only #[
				name: (col/1)
				table-oid: (col/2)
				attr-number: (col/3)
				type-oid: (col/4)
				type-size: (col/5)
				type-mod: (col/6)
				format: (col/7)
			]
		]
	]
	rt: make map! ctx/runtime
	rows: shape-rows ctx
	tag: either ctx/CommandComplete [clean-cstring any [ctx/CommandComplete ""]][none]
	row-count: none
	if all [tag string? tag not empty? tag] [
		; Best-effort parse of rowcount from CommandComplete tag.
		; Common forms: "SELECT 123", "UPDATE 7", "DELETE 4", "INSERT 0 9"
		parts: split tag #" "
		if all [2 <= length? parts integer? attempt [to integer! last parts]] [
			row-count: to integer! last parts
		]
	]
	; Build via key/value reduction to avoid compose/map literal edge-cases
	; across different Rebol builds used in CI.
	result: make map! reduce [
		'rows       rows
		'columns    cols
		'command-tag tag
		'row-count  row-count
		'notices    ctx/notices
		'runtime    rt
		'row-mode   select ctx/options 'row-mode
		'decode     select ctx/options 'decode
		'more?      to logic! ctx/PortalSuspended?
	]
	ctx/last-result: result
	result
]

queue-command: function [
	"Build packets for a write request into ctx/out-buffer"
	ctx [object!]
	data [string! word! block!]
	/local stmt sql params param-oids cursor-id info portal-name stmt-name max-rows
][
	case [
		string? data [
			que-packet ctx #"Q" join data null
		]
		word? data [
			switch data [
				SYNC      [ que-packet ctx #"S" "" ]
				TERMINATE [ que-packet ctx #"X" "Good bye!" ]
			]
		]
		block? data [
			switch/default first data [
				PREPARE [
					; [PREPARE name "SQL" [oids]]
					stmt: second data
					unless any [word? stmt string? stmt] [
						ctx/error: #[message: "PREPARE expects statement name as second item"]
						cause-error 'Access 'Protocol ctx/error
					]
					unless string? third data [
						ctx/error: #[message: "PREPARE expects SQL string as third item"]
						cause-error 'Access 'Protocol ctx/error
					]
					sql: third data
					param-oids: any [fourth data none]
					if all [param-oids not block? param-oids] [param-oids: to block! param-oids]
					; cache client-side (for reconnect / introspection)
					put ctx/prepared to word! form stmt reduce [sql param-oids]
					; Parse + Sync
					que-packet ctx #"P" make-parse-message stmt sql param-oids
					que-packet ctx #"S" ""
				]
				DEALLOCATE [
					; [DEALLOCATE name]
					stmt: second data
					unless any [word? stmt string? stmt] [
						ctx/error: compose #[message: "DEALLOCATE expects statement name as second item"]
						cause-error 'Access 'Protocol ctx/error
					]
					remove/key ctx/prepared to word! form stmt
					que-packet ctx #"C" make-close-message #"S" stmt
					que-packet ctx #"S" ""
				]
				EXEC [
					unless string? second data [
						ctx/error: compose #[message: "EXEC expects SQL string as second item"]
						cause-error 'Access 'Protocol ctx/error
					]
					sql: second data
					params: any [third data copy []]
					unless block? params [params: to block! params]
					;-- Minimal extended query flow using unnamed statement/portal:
					;   Parse + Bind + Describe(portal) + Execute + Sync
					que-packet ctx #"P" make-parse-message "" sql none
					que-packet ctx #"B" make-bind-message "" "" params
					que-packet ctx #"D" make-describe-message #"P" ""
					que-packet ctx #"E" make-execute-message "" 0
					que-packet ctx #"S" ""
				]
				EXECUTE [
					; [EXECUTE name [params]]
					stmt: second data
					unless any [word? stmt string? stmt] [
						ctx/error: compose #[message: "EXECUTE expects statement name as second item"]
						cause-error 'Access 'Protocol ctx/error
					]
					params: any [third data copy []]
					unless block? params [params: to block! params]
					que-packet ctx #"B" make-bind-message "" stmt params
					que-packet ctx #"D" make-describe-message #"P" ""
					que-packet ctx #"E" make-execute-message "" 0
					que-packet ctx #"S" ""
				]
				CURSOR [
					; [CURSOR id "SQL" [params] max-rows]
					cursor-id: second data
					unless any [word? cursor-id string? cursor-id] [
						ctx/error: compose #[message: "CURSOR expects cursor id as second item"]
						cause-error 'Access 'Protocol ctx/error
					]
					unless string? third data [
						ctx/error: compose #[message: "CURSOR expects SQL string as third item"]
						cause-error 'Access 'Protocol ctx/error
					]
					sql: third data
					params: any [fourth data copy []]
					unless block? params [params: to block! params]
					max-rows: to integer! any [fifth data 100]
					stmt-name: ajoin ["stmt-" form cursor-id]
					portal-name: ajoin ["cur-" form cursor-id]
					put ctx/cursors to word! form cursor-id reduce [stmt-name portal-name max-rows]
					; Parse (named) + Bind (named portal) + Describe (portal) + Execute(max) + Sync
					que-packet ctx #"P" make-parse-message stmt-name sql none
					que-packet ctx #"B" make-bind-message portal-name stmt-name params
					que-packet ctx #"D" make-describe-message #"P" portal-name
					que-packet ctx #"E" make-execute-message portal-name max-rows
					que-packet ctx #"S" ""
				]
				FETCH [
					; [FETCH id]
					cursor-id: second data
					unless any [word? cursor-id string? cursor-id] [
						ctx/error: compose #[message: "FETCH expects cursor id as second item"]
						cause-error 'Access 'Protocol ctx/error
					]
					info: select ctx/cursors to word! form cursor-id
					unless info [
						ctx/error: compose #[message: (ajoin ["Unknown cursor id: " form cursor-id])]
						cause-error 'Access 'Protocol ctx/error
					]
					portal-name: info/2
					max-rows: info/3
					que-packet ctx #"E" make-execute-message portal-name max-rows
					que-packet ctx #"S" ""
				]
				CLOSE-CURSOR [
					; [CLOSE-CURSOR id]
					cursor-id: second data
					unless any [word? cursor-id string? cursor-id] [
						ctx/error: compose #[message: "CLOSE-CURSOR expects cursor id as second item"]
						cause-error 'Access 'Protocol ctx/error
					]
					info: select ctx/cursors to word! form cursor-id
					unless info [
						ctx/error: compose #[message: (ajoin ["Unknown cursor id: " form cursor-id])]
						cause-error 'Access 'Protocol ctx/error
					]
					portal-name: info/2
					stmt-name: info/1
					remove/key ctx/cursors to word! form cursor-id
					que-packet ctx #"C" make-close-message #"P" portal-name
					que-packet ctx #"C" make-close-message #"S" stmt-name
					que-packet ctx #"S" ""
				]
			][
				ctx/error: compose #[
					message: (ajoin ["Unsupported write block form: " mold data])
				]
				cause-error 'Access 'Protocol ctx/error
			]
		]
	]
]

start-next-request: function [
	"Start queued async request if idle"
	pg [port!]
][
	ctx: pg/extra
	if ctx/inflight [return none]
	if empty? ctx/request-queue [return none]

	req: take ctx/request-queue
	ctx/inflight: req
	req/row-index: 0
	reset-result-state ctx
	; Optional chunked streaming using portal fetches when a max-rows is provided.
	either all [
		req/stream?
		select req 'max-rows
		integer? req/max-rows
		req/max-rows > 0
		string? req/data
	][
		req/cursor-id: to word! ajoin ["as-" form req/id]
		queue-command ctx reduce ['CURSOR req/cursor-id req/data copy [] req/max-rows]
	][
		queue-command ctx req/data
	]

	; kick IO if connection is already ready
	if all [
		ctx/ReadyForQuery
		pg/state = 'READY
	][
		pg/state: 'WRITE
		write ctx/connection take/part ctx/out-buffer 32000
	]
	req
]

finish-inflight: function [
	"Finalize inflight request and run callbacks"
	pg [port!]
][
	ctx: pg/extra
	req: ctx/inflight
	unless req [return none]

	; If streaming using portal chunks, keep fetching while suspended.
	if all [
		req/stream?
		select req 'max-rows
		integer? req/max-rows
		req/max-rows > 0
		ctx/PortalSuspended?
		select req 'cursor-id
	][
		reset-fetch-state ctx
		queue-command ctx reduce ['FETCH req/cursor-id]
		if all [
			ctx/ReadyForQuery
			pg/state = 'READY
		][
			pg/state: 'WRITE
			write ctx/connection take/part ctx/out-buffer 32000
		]
		return none
	]

	; build either result or error and invoke callbacks
	either ctx/error [
		req/status: 'error
		req/error: ctx/error
		ctx/last-error: ctx/error
		invoke-callback req/on-error ctx/error
	][
		req/status: 'done
		req/result: build-result ctx
		invoke-callback req/on-done req/result
		invoke-callback req/on-complete req/result
	]

	; Best-effort cleanup for chunked streaming: close cursor after completion.
	if all [
		req/stream?
		select req 'max-rows
		integer? req/max-rows
		req/max-rows > 0
		select req 'cursor-id
	][
		reset-fetch-state ctx
		queue-command ctx reduce ['CLOSE-CURSOR req/cursor-id]
		if all [
			ctx/ReadyForQuery
			pg/state = 'READY
		][
			pg/state: 'WRITE
			write ctx/connection take/part ctx/out-buffer 32000
		]
	]

	ctx/inflight: none
	reset-result-state ctx
	start-next-request pg
]

pg-conn-awake: function [event][
	conn:  event/port  ;; TCP or TLS port used for IO
	pg:    conn/parent ;; Higher level postgres port
	ctx:   pg/extra    ;; Context
	sys/log/debug 'POSTGRES ["State:" pg/state "event:" event/type "ref:" event/port/spec/ref]

	wake?: switch event/type [
		error [
			sys/log/error 'POSTGRES "Network error"
			close conn
			return true
		]
		lookup [
			sys/log/more 'POSTGRES "lookup..."
			open conn
			false
		]
		connect [
			;-- If TCP connect and SSL is enabled, negotiate SSLRequest first.
			if all [
				ctx/options
				select ctx/options 'sslmode <> 'disable
				none? select ctx/options 'ssl-state
				'tcp = either word? conn/scheme [conn/scheme][conn/scheme/name]
			][
				sys/log/more 'POSTGRES ["Sending SSLRequest (sslmode=" select ctx/options 'sslmode ")..."]
				put ctx/options 'ssl-state 'sslrequest
				pg/state: 'SSLREQUEST
				write conn make-sslrequest
				read conn
				return false
			]

			;-- TLS handshake finished OR plaintext connect: send StartupMessage.
			sys/log/more 'POSTGRES "Sending startup..."
			pg/state: 'WRITE
			write conn make-startup-message ctx/user ctx/database ctx/options
			false
		]

		read [
			;-- Handle 1-byte SSLRequest response before protocol parsing.
			if all [
				ctx/options
				select ctx/options 'ssl-state = 'sslrequest
				'tcp = either word? conn/scheme [conn/scheme][conn/scheme/name]
			][
				data: take/all conn/data
				if empty? data [
					read conn
					return false
				]
				reply: to char! data/1
				switch/default reply [
					#"S" [
						sys/log/more 'POSTGRES "Server accepted SSLRequest. Starting TLS..."
						put ctx/options 'ssl-state 'tls
						pg/state: 'TLS
						;-- Wrap existing TCP connection with TLS scheme.
						tls: make port! [
							scheme: 'tls
							conn: conn
							host: conn/spec/host
							port: conn/spec/port
							ref:  rejoin [tls:// host #":" port]
						]
						tls/parent: pg
						tls/awake: :pg-conn-awake
						ctx/connection: tls
						res: try [open tls]
						if error? :res [
							ctx/error: make map! reduce [
								'message "TLS negotiation failed (TLS scheme unavailable or handshake error)"
								'detail mold res
							]
							sys/log/error 'POSTGRES select ctx/error 'message
							close conn
							return true
						]
						return false
					]
					#"N" [
						sys/log/more 'POSTGRES "Server refused SSLRequest."
						put ctx/options 'ssl-state 'plaintext
						if select ctx/options 'sslmode = 'require [
							ctx/error: make map! reduce [
								'message "Server does not support TLS (SSLRequest refused) and sslmode=require"
							]
							sys/log/error 'POSTGRES select ctx/error 'message
							close conn
							return true
						]
						;-- Continue plaintext by sending StartupMessage.
						sys/log/more 'POSTGRES "Continuing in plaintext (sslmode=prefer)."
						pg/state: 'WRITE
						write conn make-startup-message ctx/user ctx/database ctx/options
						return false
					]
				][
					ctx/error: make map! reduce [
						'message ajoin ["Unexpected SSLRequest response byte: " mold reply]
					]
					sys/log/error 'POSTGRES select ctx/error 'message
					close conn
					return true
				]
			]

			process-responses ctx
			case [
				all [
					ctx/error
					not ctx/authenticated?
				][
					;; When there is error in the authentication process
					;; we cannot continue processing any input/output!
				]
				not empty? ctx/inp-buffer [
					;; Responses were not complete, so continue reading...
					read conn
					return false
				]
				not empty? ctx/out-buffer [
					;; There are new qued packets, so write these...
					pg/state: 'WRITE
					write conn take/part ctx/out-buffer 32000
					return false
				]
				'else [
					pg/state: 'READY
				]
			]

			;-- If an async request is inflight, complete it when server is ready.
			;   (ReadyForQuery may also appear during handshake; inflight guards that.)
			if all [
				pg/state = 'READY
				ctx/ReadyForQuery
				ctx/inflight
			][
				finish-inflight pg
			]

			true
		]
		wrote [
			;; Never wake up here. Instead...
			either empty? ctx/out-buffer [
				;; ...read a response.
				pg/state: 'READ
				read conn
			][	;; ...continue sending packets.
				write conn take/part ctx/out-buffer 32000
			]
			false
		]
		close [
			; If the underlying socket closes unexpectedly while a request is inflight,
			; surface it as a protocol error. Otherwise treat it as a normal close.
			if all [ctx ctx/inflight] [
				ctx/error: make map! reduce ['message "Port closed on me"]
			]
		]
	]
	if ctx/error [
		;; force wake-up to report error in all cases.
		wake?: true
		pg/state: 'ERROR
	]
	if wake? [
		;-- Report user that the port wants to wake up...
		;;; so user may use:
		;;; pg: open postgress://localhost
		;;; wait pg
		insert system/ports/system make event! [type: pg/state port: pg]
	]
	wake?
]

sys/make-scheme [
	name: 'postgres
	title: "POSTGRES Protocol"
	spec: make system/standard/port-spec-net [port: 5432 timeout: 15]

	awake: func [event /local port parent ctx] [
		;@@TODO: review this... it should be handle event from an inner TCP connection..
		sys/log/debug 'POSTGRES ["Awake:^[[22m" event/type]

		port: event/port
		ctx: port/extra
		switch event/type [
			ready [
				return true ;; awakes
			]
			close [
				close port
				return true
			]
			error [
				unless ctx/authenticated? [
					sys/log/error 'POSTGRES ctx/error
					;; If there was error in the authentication prosess, than it is fatal!
					close port
				]
				return true
			]
		]
		false
	]
	actor: [
		open: func [
			port [port!]
			/local conn spec user database db params allowed-auth sslmode row-mode decode-mode
			connect-timeout query-timeout app-name search-path log-level trace? handshake-timeout
		] [
			if port/extra [return port]

			spec: port/spec

			user: any [select spec 'user "postgres"]
			database: any [
				all [
					spec/path
					not empty? db: form spec/path
					either db/1 = #"/" [next db][db]
				]
				user
			]

			port/extra: object [
				user:
				database:
				options:
				connection:
				awake: :port/awake
				state: none
				error: none
				last-error: none
				last-result: none
				request-queue: make block! 10
				inflight: none
				next-req-id: 0
				runtime: make block! 30
				notices: make block! 10
				out-buffer: make binary! 1000
				inp-buffer: make binary! 1000
				authenticated?: false
				CancelKeyData:
				ReadyForQuery: none
				RowDescription: make block! 20
				Data: make block! 1000
				CommandComplete: none
				PortalSuspended?: false
				prepared: make map! 20   ; statement-name -> [sql param-oids]
				cursors:  make map! 10   ; cursor-id -> [stmt portal max-rows]
				notify-handlers: make map! 20 ; channel(string) -> [handlers...]
				notify-any: none              ; optional catch-all handler
				sasl: context [
					;; input values...
					user:     user
					password: any [select spec 'pass "postgres"]
					mechanism: none
					mechanisms: copy []
					salt: none
					iterations: 4096
					method: 'sha256
					gs2-header: "n,,"
					client-first-message-bare:
					server-first-message:
					client-final-message-without-proof:
					;; output values...
					SaltedPassword:
					ClientKey:
					ServerKey:
					StoredKey:
					AuthMessage:
					ClientSignature:
					ServerSignature:
					ClientProof: none
				]
			]
			port/extra/user: user
			;; sasl/user suffers a self-referential binding issue inside the object
			;; literal (the word 'user is rebound to sasl's own field, which is none).
			;; Set it explicitly here after the object is fully constructed.
			port/extra/sasl/user: user
			params: parse-query-params spec/query
			allowed-auth: any [
				all [select params 'auth parse-auth-list select params 'auth]
				[ scram md5 cleartext ]
			]
			sslmode: parse-sslmode select params 'sslmode
			row-mode: parse-row-mode select params 'row
			decode-mode: parse-decode-mode select params 'decode
			connect-timeout: parse-timeout-seconds any [select params 'connect-timeout select params 'connect_timeout]
			query-timeout: parse-timeout-seconds any [select params 'query-timeout select params 'query_timeout]
			app-name: any [select params 'application_name select params 'application-name]
			search-path: any [select params 'search_path select params 'search-path]
			log-level: parse-log-level select params 'log
			trace?: parse-trace-flag any [select params 'trace select params 'debug]
			port/extra/options: make map! reduce [
				'auth allowed-auth
				'allow-cleartext? not none? find allowed-auth 'cleartext
				'sslmode sslmode
				'ssl-state none
				'row-mode row-mode
				'decode decode-mode
				'connect-timeout connect-timeout
				'query-timeout query-timeout
				'application_name app-name
				'search_path search-path
				'trace? trace?
			]
			database: any [select params 'database database]
			port/extra/database: database

			; Optional: set logging verbosity from URL.
			if integer? :log-level [system/options/log/postgres: log-level]

			port/state: 'INIT

			port/extra/connection: conn: make port! [
				scheme: 'tcp
				host: spec/host
				port: spec/port
				ref:  rejoin [tcp:// host #":" port]
			]

			;; `ref` is used in logging and errors
			;; reconstruct it so password is not visible!
            spec/ref: as url! ajoin [spec/scheme "://" select spec 'user #"@" spec/host #":" spec/port]

			conn/parent: port
			conn/awake: :pg-conn-awake
			open conn
			;; wait for the handshake...
			handshake-timeout: any [connect-timeout 10]
			unless port? wait [conn handshake-timeout][
				sys/log/error 'POSTGRES "Failed to connect!"
			]

			;; If the handshake or authentication failed the awake handler calls
			;; `close port`, which sets port/extra to none.  Surface that as a
			;; proper error instead of letting the next path access crash.
			unless port/extra [
				cause-error 'Access 'Protocol make map! reduce [
					'message "PostgreSQL connection failed during handshake (check server logs for details)"
				]
			]

			; Optional session initialization (after open succeeds).
			if all [port/extra/options select port/extra/options 'search_path] [
				; treat as part of open; errors should surface
				sp: format-search-path select port/extra/options 'search_path
				if sp [
					write port ajoin ["SET search_path TO " sp ";"]
				]
			]

			port
		]

		open?: func [port [port!] /local conn][
			not none? all [
				port/extra
				port? conn: port/extra/connection
				open? conn
			]
		]

		close: func [ port [port!]] [
			if open? port [
				sys/log/debug 'POSTGRES "Closing connection."
				;; just closing the TCP connection?
				close port/extra/connection
				port/extra: port/state: none
			]
		]

		write: func [
			port [port!]
			data [string! word! block!]
			/local ctx req on-row on-done on-complete on-error blk req-data max-rows arg6 arg7 timeout
		][
			unless open? port [
				cause-error 'Access 'not-open port/spec/ref
			]
			ctx: port/extra
			;-- Async streaming block form:
			;   [ASYNC-STREAM <data> :on-row :on-done :on-error]
			;   [ASYNC-STREAM <data> :on-row :on-done :on-error max-rows]
			;   [ASYNC-STREAM <data> :on-row :on-done :on-error :on-complete max-rows]
			if all [block? data 'ASYNC-STREAM = first data] [
				blk: data
				req-data: second blk
				on-row: any [third blk none]
				on-done: any [fourth blk none]
				on-error: any [fifth blk none]
				on-complete: none
				max-rows: 0
				arg6: any [sixth blk none]
				arg7: any [seventh blk none]
				either integer? :arg6 [
					max-rows: arg6
				][
					on-complete: arg6
					if integer? :arg7 [max-rows: arg7]
				]

				ctx/next-req-id: ctx/next-req-id + 1
				req: make object! [
					id: none
					status: 'pending
					data: none
					stream?: true
					row-index: 0
					max-rows: 0
					cursor-id: none
					on-row: none
					on-done: none
					on-complete: none
					on-error: none
					result: none
					error: none
				]
				req/id: ctx/next-req-id
				req/data: req-data
				req/max-rows: to integer! max-rows
				req/on-row: on-row
				req/on-done: on-done
				req/on-complete: on-complete
				req/on-error: on-error
				append ctx/request-queue req
				start-next-request port
				return req
			]

			;-- Async block form: [ASYNC <data> :on-done :on-error]
			if all [block? data 'ASYNC = first data] [
				blk: data
				req-data: second blk
				on-done: any [third blk none]
				on-error: any [fourth blk none]

				ctx/next-req-id: ctx/next-req-id + 1
				req: make object! [
					id: none
					status: 'pending
					data: none
					stream?: false
					row-index: 0
					on-row: none
					on-done: none
					on-complete: none
					on-error: none
					result: none
					error: none
				]
				req/id: ctx/next-req-id
				req/data: req-data
				req/on-row: none
				req/on-done: on-done
				req/on-complete: none
				req/on-error: on-error
				append ctx/request-queue req
				start-next-request port
				return req
			]

			reset-result-state ctx
			queue-command ctx data

			; TERMINATE closes the connection; server won't send ReadyForQuery.
			if all [word? data data = 'TERMINATE] [
				if all [
					ctx/ReadyForQuery
					port/state = 'READY
				][
					port/state: 'WRITE
					write ctx/connection take/part ctx/out-buffer 32000
				]
				close port
				return port
			]

			if all [
				ctx/ReadyForQuery
				port/state = 'READY
			][
				port/state: 'WRITE
				write ctx/connection take/part ctx/out-buffer 32000
			]
			timeout: any [
				all [ctx/options integer? select ctx/options 'query-timeout select ctx/options 'query-timeout]
				port/spec/timeout
			]
			unless wait [port timeout][
				;; wait returns none in case of timeout...
				cause-error 'Access 'Timeout port/spec/ref
			]
			;@@ TODO: improve!
			return case [
				ctx/error [
					port/state: 'READY
					ctx/last-error: ctx/error
					cause-error 'Access 'Protocol ctx/error
				]
				ctx/PortalSuspended? [
					; partial result (cursor/chunked)
					build-result ctx
				]
				ctx/CommandComplete [
					build-result ctx
				]
			]
		]

		read: func [
			port [port!]
			/local ctx
		][
			unless open? port [
				cause-error 'Access 'not-open port/spec/ref
			]
			ctx: port/extra
			; Kick a read on the underlying TCP/TLS connection; parsing happens in awake.
			read ctx/connection
			port
		]
	]
]
