/*
 * Copyright 2012 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.util.internal;

import org.junit.Test;

import static io.netty.util.internal.StringUtil.*;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

public class StringUtilTest {

    @Test
    public void ensureNewlineExists() {
        assertNotNull(NEWLINE);
    }

    @Test
    public void testToHexString() {
        assertThat(toHexString(new byte[] { 0 }), is("0"));
        assertThat(toHexString(new byte[] { 1 }), is("1"));
        assertThat(toHexString(new byte[] { 0, 0 }), is("0"));
        assertThat(toHexString(new byte[] { 1, 0 }), is("100"));
        assertThat(toHexString(EmptyArrays.EMPTY_BYTES), is(""));
    }

    @Test
    public void testToHexStringPadded() {
        assertThat(toHexStringPadded(new byte[]{0}), is("00"));
        assertThat(toHexStringPadded(new byte[]{1}), is("01"));
        assertThat(toHexStringPadded(new byte[]{0, 0}), is("0000"));
        assertThat(toHexStringPadded(new byte[]{1, 0}), is("0100"));
        assertThat(toHexStringPadded(EmptyArrays.EMPTY_BYTES), is(""));
    }

    @Test
    public void splitSimple() {
        assertArrayEquals(new String[] { "foo", "bar" }, split("foo:bar", ':'));
    }

    @Test
    public void splitWithTrailingDelimiter() {
        assertArrayEquals(new String[] { "foo", "bar" }, split("foo,bar,", ','));
    }

    @Test
    public void splitWithTrailingDelimiters() {
        assertArrayEquals(new String[] { "foo", "bar" }, split("foo!bar!!", '!'));
    }

    @Test
    public void splitWithConsecutiveDelimiters() {
        assertArrayEquals(new String[] { "foo", "", "bar" }, split("foo$$bar", '$'));
    }

    @Test
    public void splitWithDelimiterAtBeginning() {
        assertArrayEquals(new String[] { "", "foo", "bar" }, split("#foo#bar", '#'));
    }

    @Test
    public void splitMaxPart() {
        assertArrayEquals(new String[] { "foo", "bar:bar2" }, split("foo:bar:bar2", ':', 2));
        assertArrayEquals(new String[] { "foo", "bar", "bar2" }, split("foo:bar:bar2", ':', 3));
    }

    @Test
    public void substringAfterTest() {
        assertEquals("bar:bar2", substringAfter("foo:bar:bar2", ':'));
    }
}
