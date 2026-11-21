package infernics.notes

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test

class NoteOrderingTest {
    @Test
    fun draggingOneNoteOntoAnotherSwapsTheirPositions() {
        val first = Note(id = "first", title = "First")
        val second = Note(id = "second", title = "Second")
        val third = Note(id = "third", title = "Third")

        val result = swapNotePositions(listOf(first, second, third), "first", "third")

        assertEquals(listOf("third", "second", "first"), result.map { it.id })
        assertEquals(listOf("first", "second", "third"), listOf(first, second, third).map { it.id })
    }

    @Test
    fun missingOrSameTargetDoesNotChangeTheList() {
        val notes = listOf(Note(id = "first"), Note(id = "second"))

        assertSame(notes, swapNotePositions(notes, "first", "missing"))
        assertSame(notes, swapNotePositions(notes, "first", "first"))
    }
}
