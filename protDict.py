prot_dict = {
                'IP':
                    {
                        'version': {'low': 0, 'high': 15         },
                        'ttl':     {'low': 0, 'high': 255        },
                        'ihl':     {'low': 0, 'high': 15         },
                        'tos':     {'low': 0, 'high': 255        },
                        'len':     {'low': 0, 'high': 65535      },
                        'id':      {'low': 0, 'high': 65535      },
                        'frag':    {'low': 0, 'high': 8191       },
                        'proto':   {'low': 0, 'high': 255        },
                        'chksum':  {'low': 0, 'high': 65535      }
                    },
                'TCP':
                    {
                        'sport':    {'low': 0, 'high': 65535     },
                        'dport':    {'low': 0, 'high': 65535     },
                        'seq':      {'low': 0, 'high': 4294967295},
                        'ack':      {'low': 0, 'high': 4294967295},
                        'dataofs':  {'low': 0, 'high': 15        },
                        'reserved': {'low': 0, 'high': 8         },
                        'window':   {'low': 0, 'high': 65535     },
                        'chksum':   {'low': 0, 'high': 65535     },
                        'urgptr':   {'low': 0, 'high': 65535     }
                    },
                'UDP':
                    {
                        'sport':    {'low': 0, 'high': 65535     },
                        'dport':    {'low': 0, 'high': 65535     },
                        'len':      {'low': 0, 'high': 65535     },
                        'chksum':   {'low': 0, 'high': 65535     }
                    },
                'ICMP':
                    {
                        'type':       {'low': 0, 'high': 255       },
                        'code':       {'low': 0, 'high': 255       },
                        'chksum':     {'low': 0, 'high': 65535     },
                        'id':         {'low': 0, 'high': 65535     },
                        'seq':        {'low': 0, 'high': 65535     },
                        'ts_ori':     {'low': 0, 'high': 4294967295},
                        'ts_rx':      {'low': 0, 'high': 4294967295},
                        'ts_tx':      {'low': 0, 'high': 4294967295},
                        'ptr':        {'low': 0, 'high': 255       },
                        'reserved':   {'low': 0, 'high': 255       },
                        'length':     {'low': 0, 'high': 255       },
                        'nexthopmtu': {'low': 0, 'high': 65535     }
                    },
                'DNS':
                    {
                        'length':   {'low': 0, 'high': 65535     },
                        'id':       {'low': 0, 'high': 65535     },
                        'qr':       {'low': 0, 'high': 1         },
                        'opcode':   {'low': 0, 'high': 15        },
                        'aa':       {'low': 0, 'high': 1         },
                        'tc':       {'low': 0, 'high': 1         },
                        'rd':       {'low': 0, 'high': 1         },
                        'ra':       {'low': 0, 'high': 1         },
                        'z':        {'low': 0, 'high': 1         },
                        'ad':       {'low': 0, 'high': 1         },
                        'cd':       {'low': 0, 'high': 1         },
                        'rcode':    {'low': 0, 'high': 15        },
                        'qdcount':  {'low': 0, 'high': 65535     },
                        'ancount':  {'low': 0, 'high': 65535     },
                        'nscount':  {'low': 0, 'high': 65535     },
                        'arcount':  {'low': 0, 'high': 65535     }
                    },
                'DNSQR':
                    {
                        'qtype':           {'low': 0, 'high': 65535},
                        'unicastresponse': {'low': 0, 'high': 1    },
                        'qclass':          {'low': 0, 'high': 32767}
                    },
                'DNSRR':
                    {
                        'type':       {'low': 0, 'high': 65535     },
                        'cacheflush': {'low': 0, 'high': 1         },
                        'rclass':     {'low': 0, 'high': 32767     },
                        'ttl':        {'low': 0, 'high': 4294967295},
                        'rdlen':      {'low': 0, 'high': 65535     }
                    },
                'DNSRROPT':
                    {
                        'type':     {'low': 0, 'high': 65535},
                        'rclass':   {'low': 0, 'high': 65535},
                        'extrcode': {'low': 0, 'high': 255  },
                        'version':  {'low': 0, 'high': 255  },
                        'z':        {'low': 0, 'high': 65535},
                        'rdlen':    {'low': 0, 'high': 65535}
                    },
                'TLS':
                    {
                        'type':    {'low': 0, 'high': 255  },
                        'version': {'low': 0, 'high': 65535},
                        'len':     {'low': 0, 'high': 65535}
                    }
            }
