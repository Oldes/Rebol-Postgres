Rebol [
	Name:    postgres
	Type:    module
	Options: [delay]
	Version: 0.1.0
	Date:    28-Feb-2025
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
	;@@ TODO: use authentication aaccording server's preferences!!!
	nonce: make binary! 24
	binary/write nonce [random-bytes 24]
	ctx/sasl/client-first-message-bare: ajoin [
		"n=" ctx/sasl/user ",r=" enbase nonce 64
	]
	msg: join ctx/sasl/gs2-header ctx/sasl/client-first-message-bare
	response: clear #{}
	binary/write response [
		BYTES     "SCRAM-SHA-256^@"
		UI32BYTES :msg
	]
	response
]

make-startup-message: funct [
	;- This packet is special and so is not used in a output que!
	user     [string!]
	database [string!]
] [
	; Send StartupMessage
	startup-message: rejoin [
		#{00000000} ; Length placeholder
		#{00030000} ; Protocol version (3.0)
		"user^@"     user     null ; Default username
		"database^@" database null ; Default database
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
	sys/log/debug 'POSTGRES ["Client-> type:" as-blue type as-yellow mold msg]
	len: 4 + length? msg
	binary/write out [
		UI8 :type
		UI32 :len
		BYTES :msg
	]
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
	;? ctx
	while [5 <= length? bin/buffer][
		binary/read bin [
			type: UI8
			len:  UI32
		]
		;sys/log/debug 'POSTGRES ["Process responses length:" len "buff:" length? bin/buffer]
		if (len - 4) > length? bin/buffer [
			print "not complete!"
			break
		]
		type: to char! type
		;? type
		switch/default/case type [
			#"R" [
				auth-id: binary/read bin 'UI32
				sys/log/more 'POSTGRES ["Authentication message type:" as-yellow auth-id]
				switch/default auth-id [
					0 [
						;; Specifies that the authentication was successful.
						ctx/authenticated?: true
					]
					10 [
						;; The message body is a list of SASL authentication mechanisms,
						;; in the server's order of preference. A zero byte is required
						;; as terminator after the last authentication mechanism name.
						tmp: clear ctx/sasl/mechanisms
						until [
							name: binary/read bin 'STRING
							none? unless empty? name [
								append tmp to word! name
							]
						]
						;; pg/state: 'AuthenticationSASL
						sys/log/debug 'POSTGRES "Writing authenticate"
						que-packet ctx #"p" authenticate ctx
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
					append ctx/RowDescription tmp: binary/read bin [
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
				;@@ TODO: keep this info for later use!!!
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
				append ctx/data row
			]
			#"C" [
				;; Identifies the message as a command-completed response.
				;@@ TODO: process the result!!!
				ctx/CommandComplete: tmp: to string! binary/read bin len - 4
				sys/log/more 'POSTGRES ["Command completed:^[[m" tmp]
			]
			#"E" [
				err: clear []
				while [0 != type: binary/read bin 'UI8][
					append err type
					append err binary/read bin 'STRING
				]
				sys/log/debug 'POSTGRES ["ERROR:" mold err]
				sys/log/error 'POSTGRES [err/8]
				ctx/error: err/8
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
			#"Z" [
				;; Identifies the message type.
				;; ReadyForQuery is sent whenever the backend is ready for a new query cycle.
				ctx/ReadyForQuery: to char! binary/read bin 'UI8
				sys/log/more 'POSTGRES ["ReadyForQuery:" ctx/ReadyForQuery]
			]
		][
			sys/log/error 'POSTGRES ["Unknown message type:" type]
			binary/read bin len - 4
		]
		;@@ TODO: validate that correct length of data was consumed!
	]
	;; Remove all processed data from the head of the input buffer
	truncate bin/buffer
	;; Return true if the input buffer is empty
	tail? bin/buffer
]



pg-conn-awake: function [event][
	conn:  event/port  ;; The real TCP connection
	pg:    conn/parent ;; Higher level postgress port
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
			sys/log/more 'POSTGRES "Sending startup..."
			pg/state: 'WRITE
			write conn make-startup-message "postgres" "postgres"
			false
		]

		read [
			process-responses ctx
			;? ctx/out-buffer
			;? ctx/inp-buffer
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
			ctx/error: "Port closed on me"
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
			/local conn spec
		] [
			if port/extra [return port]

			spec: port/spec
			;? spec

			port/extra: object [	
				connection:
				awake: :port/awake
				state: none
				error: none
				runtime: make block! 30
				out-buffer: make binary! 1000
				inp-buffer: make binary! 1000
				authenticated?: false
				sync-read?: true
				CancelKeyData:
				ReadyForQuery: none
				RowDescription: make block! 20
				Data: make block! 1000
				CommandComplete: none
				sasl: context [
					;; input values...
					user:     any [spec/user "postgres"]
					password: any [spec/pass "postgres"]
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

			port/state: 'INIT

			port/extra/connection: conn: make port! [
				scheme: 'tcp
				host: spec/host
				port: spec/port
				ref:  rejoin [tcp:// host #":" port]
			]
			conn/parent: port
			conn/awake: :pg-conn-awake
			open conn
			;; wait for the handshake...
			unless port? wait [conn 10][
				sys/log/error 'POSTGRES "Failed to connect!"
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
			data
			/local ctx
		][
			unless open? port [
				print "not open"
				return none
			]
			ctx: port/extra
			if string? data [
				ctx/error: none
				ctx/CommandComplete: none
				clear ctx/Data
				clear ctx/RowDescription

				que-packet ctx #"Q" join data null
				if all [
					ctx/ReadyForQuery
					port/state = 'READY
				][
					port/state: 'WRITE
					write ctx/connection take/part ctx/out-buffer 32000
				]
			]
			if all [
				ctx/sync-read?
				port? wait [port port/spec/timeout]
			][
				;@@ TODO: improve!
				return case [
					ctx/error [
						make error! [
							type: 'Access
							id: 'Protocol
							arg1: ctx/error
						]
					]
					ctx/CommandComplete [ ctx/Data ]
				]
			]
			port
		]
		
		read: func [
			port [port!]
		][
			;@@TODO: review this...
		]
	]
]
