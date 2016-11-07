/*
 * Copyright (c) 2013-2014 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dnstap

import "log"
import "io"
import "os"

import framestream "github.com/farsightsec/golang-framestream"

type FrameStreamInput struct {
    wait        chan bool
    decoder     *framestream.Decoder
}

func NewFrameStreamInput(r io.ReadWriter, bi bool) (input *FrameStreamInput, err error) {
    input = new(FrameStreamInput)
    decoderOptions := framestream.DecoderOptions{
        ContentType: FSContentType,
        Bidirectional: bi,
    }
    input.decoder, err = framestream.NewDecoder(r, &decoderOptions)
    if err != nil {
        return
    }
    input.wait = make(chan bool)
    return
}

func NewFrameStreamInputFromFilename(fname string) (input *FrameStreamInput, err error) {
    file, err := os.Open(fname)
    if err != nil {
        return nil, err
    }
    input, err = NewFrameStreamInput(file, false)
    return
}

func (input *FrameStreamInput) ReadInto(number_of_records int64, output chan []byte) {
    var current_iteration int64 = 0
    
    for {
        current_iteration++

        // If we need only certain number of records just stop loop
        if number_of_records != -1 && current_iteration > number_of_records {
            break
        } 

        buf, err := input.decoder.Decode()
        if err != nil {
            if err != io.EOF {
                log.Printf("framestream.Decoder.Decode() failed: %s\n", err)
            }
            break
        }
        newbuf := make([]byte, len(buf))
        copy(newbuf, buf)
        output <- newbuf
    }
    close(input.wait)
}

func (input *FrameStreamInput) Wait() {
    <-input.wait
}
