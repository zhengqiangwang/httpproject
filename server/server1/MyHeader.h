#ifndef MYHEADER_H
#define MYHEADER_H

#include <stdio.h>
#include <mutex>
#include <thread>
#include <string>
#include <map>
#include <vector>
#include <iostream>
#include <memory>
#include <unordered_map>

#include "event2/bufferevent.h"
#include "event2/buffer.h"
#include "event2/listener.h"
#include "event2/util.h"
#include "event2/event_compat.h"
#include "event2/event.h"
#include "event2/keyvalq_struct.h"
#include "event2/http.h"
#include "event2/http_struct.h"
#include "event2/http_compat.h"

using std::mutex;
using std::thread;
using std::string;
using std::map;
using std::vector;

#endif // MYHEADER_H
